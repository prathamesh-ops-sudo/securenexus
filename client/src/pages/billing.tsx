import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  CreditCard,
  Crown,
  Building2,
  Zap,
  Download,
  ExternalLink,
  AlertTriangle,
  Check,
  ArrowRight,
  Loader2,
  Shield,
  Activity,
  Brain,
  Plug,
  FileText,
  RefreshCw,
} from "lucide-react";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function statusBadge(status: string) {
  const styles: Record<string, string> = {
    active: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    trialing: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    past_due: "bg-red-500/10 text-red-400 border-red-500/30",
    cancelled: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
    paused: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    paid: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    open: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    draft: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
    void: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  };
  return (
    <Badge variant="outline" className={styles[status] || "bg-zinc-500/10 text-zinc-400 border-zinc-500/30"}>
      {status.replace("_", " ").toUpperCase()}
    </Badge>
  );
}

function usageIcon(metric: string) {
  switch (metric) {
    case "alerts_ingested":
      return <Activity className="h-4 w-4" />;
    case "connectors":
      return <Plug className="h-4 w-4" />;
    case "ai_analyses":
      return <Brain className="h-4 w-4" />;
    case "api_calls":
      return <Zap className="h-4 w-4" />;
    case "playbooks":
      return <FileText className="h-4 w-4" />;
    case "api_keys":
      return <Shield className="h-4 w-4" />;
    case "users":
      return <Building2 className="h-4 w-4" />;
    case "connector_syncs":
      return <RefreshCw className="h-4 w-4" />;
    default:
      return <Activity className="h-4 w-4" />;
  }
}

function usageLabel(metric: string) {
  switch (metric) {
    case "alerts_ingested":
      return "Alerts Ingested";
    case "connectors":
      return "Active Connectors";
    case "ai_analyses":
      return "AI Analyses";
    case "api_calls":
      return "API Calls";
    case "playbooks":
      return "Playbooks";
    case "api_keys":
      return "API Keys";
    case "users":
      return "Team Members";
    case "connector_syncs":
      return "Connector Syncs";
    default:
      return metric.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }
}

function progressColor(pct: number): string {
  if (pct >= 95) return "bg-red-500";
  if (pct >= 80) return "bg-yellow-500";
  return "bg-emerald-500";
}

function CurrentPlanSection() {
  const { data: subData, isLoading: subLoading } = useQuery({
    queryKey: ["/api/billing/subscription"],
  });
  const { data: usageData, isLoading: usageLoading } = useQuery({
    queryKey: ["/api/billing/usage-vs-limits"],
  });

  const sub = (subData as any)?.data || subData;
  const usage = (usageData as any)?.data || usageData;

  if (subLoading || usageLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32" />
        <div className="grid grid-cols-2 gap-4">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      </div>
    );
  }

  const plan = sub?.plan;
  const subscription = sub?.subscription;
  const status = sub?.status || "active";
  const isFreePlan = sub?.isFreePlan !== false;

  return (
    <div className="space-y-4">
      <Card className="glass-card border-border/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                <Crown className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <CardTitle className="text-lg">{plan?.displayName || "Free"} Plan</CardTitle>
                <CardDescription>
                  {isFreePlan
                    ? "Upgrade to unlock more features and higher limits"
                    : `${subscription?.billingCycle === "annual" ? "Annual" : "Monthly"} billing`}
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {statusBadge(status)}
              {subscription?.cancelledAt && (
                <Badge variant="outline" className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                  Cancels {formatDate(subscription.currentPeriodEnd)}
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-baseline gap-2 mb-4">
            <span className="text-3xl font-bold">
              {plan?.monthlyPriceCents ? formatCents(plan.monthlyPriceCents) : "$0"}
            </span>
            <span className="text-muted-foreground text-sm">/month</span>
          </div>
          {subscription?.currentPeriodEnd && (
            <p className="text-sm text-muted-foreground">Next renewal: {formatDate(subscription.currentPeriodEnd)}</p>
          )}
        </CardContent>
      </Card>

      {usage?.usage && (
        <>
          {Object.values(
            usage.usage as Record<string, { current: number; limit: number; pct: number; status: string }>,
          ).some((m) => m.status === "critical") && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400 shrink-0" />
              <div>
                <p className="text-sm font-medium text-red-400">Plan limit reached</p>
                <p className="text-xs text-red-400/70">
                  Some resources have hit their plan limits. New operations will be blocked until you upgrade.
                </p>
              </div>
              <Button
                size="sm"
                variant="outline"
                className="ml-auto border-red-500/30 text-red-400 hover:bg-red-500/10 shrink-0"
                onClick={() => document.getElementById("plans-tab")?.click()}
              >
                Upgrade <ArrowRight className="h-3 w-3 ml-1" />
              </Button>
            </div>
          )}
          {!Object.values(
            usage.usage as Record<string, { current: number; limit: number; pct: number; status: string }>,
          ).some((m) => m.status === "critical") &&
            Object.values(
              usage.usage as Record<string, { current: number; limit: number; pct: number; status: string }>,
            ).some((m) => m.status === "warning") && (
              <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-yellow-400 shrink-0" />
                <div>
                  <p className="text-sm font-medium text-yellow-400">Approaching plan limits</p>
                  <p className="text-xs text-yellow-400/70">
                    Some resources are nearing their plan limits. Consider upgrading to avoid disruptions.
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  className="ml-auto border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10 shrink-0"
                  onClick={() => document.getElementById("plans-tab")?.click()}
                >
                  Upgrade <ArrowRight className="h-3 w-3 ml-1" />
                </Button>
              </div>
            )}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(
              usage.usage as Record<string, { current: number; limit: number; pct: number; status: string }>,
            )
              .filter(([_, m]) => m.limit !== -1)
              .map(([key, metric]) => (
                <Card
                  key={key}
                  className={`glass-card border-border/50 ${
                    metric.status === "critical"
                      ? "border-red-500/30"
                      : metric.status === "warning"
                        ? "border-yellow-500/30"
                        : ""
                  }`}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span
                        className={`${
                          metric.status === "critical"
                            ? "text-red-400"
                            : metric.status === "warning"
                              ? "text-yellow-400"
                              : "text-muted-foreground"
                        }`}
                      >
                        {usageIcon(key)}
                      </span>
                      <span className="text-sm font-medium">{usageLabel(key)}</span>
                      <span
                        className={`ml-auto text-xs ${
                          metric.status === "critical"
                            ? "text-red-400 font-semibold"
                            : metric.status === "warning"
                              ? "text-yellow-400"
                              : "text-muted-foreground"
                        }`}
                      >
                        {metric.pct}%
                      </span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${progressColor(metric.pct)}`}
                        style={{ width: `${Math.min(metric.pct, 100)}%` }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {metric.current.toLocaleString()} / {metric.limit.toLocaleString()}
                    </p>
                  </CardContent>
                </Card>
              ))}
          </div>
        </>
      )}
    </div>
  );
}

function PlanComparisonSection() {
  const { data: plansData, isLoading } = useQuery({
    queryKey: ["/api/billing/plans"],
  });
  const { data: subData } = useQuery({
    queryKey: ["/api/billing/subscription"],
  });
  const { toast } = useToast();

  const allPlans = ((plansData as any)?.data || plansData || []) as any[];
  const sub = (subData as any)?.data || subData;
  const currentPlanName = sub?.plan?.name || "free";

  const checkoutMutation = useMutation({
    mutationFn: async (params: { planId: string; billingCycle: string }) => {
      const res = await apiRequest("POST", "/api/billing/checkout-session", {
        planId: params.planId,
        billingCycle: params.billingCycle,
        successUrl: `${window.location.origin}/billing?success=true`,
        cancelUrl: `${window.location.origin}/billing?cancelled=true`,
      });
      return res.json();
    },
    onSuccess: (data: any) => {
      const url = data?.data?.url || data?.url;
      if (url) {
        window.location.href = url;
      } else {
        toast({
          title: "Stripe not configured",
          description: "Contact sales to upgrade your plan.",
          variant: "default",
        });
      }
    },
    onError: (err: Error) => {
      toast({ title: "Checkout failed", description: err.message, variant: "destructive" });
    },
  });

  const defaultPlans = [
    {
      name: "free",
      displayName: "Free",
      description: "For evaluation and small teams",
      monthlyPriceCents: 0,
      features: { events: "10K", connectors: 3, aiTokens: "5K", automations: 100 },
    },
    {
      name: "pro",
      displayName: "Pro",
      description: "For growing security teams",
      monthlyPriceCents: 4900,
      features: { events: "100K", connectors: 25, aiTokens: "50K", automations: 1000 },
    },
    {
      name: "enterprise",
      displayName: "Enterprise",
      description: "Unlimited scale with SLA",
      monthlyPriceCents: 19900,
      features: { events: "Unlimited", connectors: "Unlimited", aiTokens: "1M+", automations: "50K+" },
    },
  ];

  const displayPlans = allPlans.length > 0 ? allPlans : defaultPlans;

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Skeleton className="h-80" />
        <Skeleton className="h-80" />
        <Skeleton className="h-80" />
      </div>
    );
  }

  const tierColors: Record<string, string> = {
    free: "border-zinc-500/30",
    pro: "border-cyan-500/30",
    enterprise: "border-purple-500/30",
    custom: "border-amber-500/30",
  };

  const tierIcons: Record<string, React.ReactNode> = {
    free: <Shield className="h-5 w-5 text-zinc-400" />,
    pro: <Zap className="h-5 w-5 text-cyan-400" />,
    enterprise: <Building2 className="h-5 w-5 text-purple-400" />,
    custom: <Crown className="h-5 w-5 text-amber-400" />,
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {displayPlans.map((plan: any) => {
        const isCurrent = plan.name === currentPlanName;
        const features = plan.features || {};
        const borderClass = tierColors[plan.name] || "border-border/50";

        return (
          <Card
            key={plan.name}
            className={`glass-card relative ${borderClass} ${isCurrent ? "ring-2 ring-cyan-500/30" : ""}`}
          >
            {isCurrent && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30">Current Plan</Badge>
              </div>
            )}
            <CardHeader className="pb-2 pt-5">
              <div className="flex items-center gap-2 mb-1">
                {tierIcons[plan.name] || <Shield className="h-5 w-5" />}
                <CardTitle className="text-lg">{plan.displayName}</CardTitle>
              </div>
              <CardDescription>{plan.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-baseline gap-1">
                <span className="text-2xl font-bold">
                  {plan.monthlyPriceCents === 0
                    ? "$0"
                    : plan.name === "custom"
                      ? "Custom"
                      : formatCents(plan.monthlyPriceCents)}
                </span>
                {plan.monthlyPriceCents > 0 && plan.name !== "custom" && (
                  <span className="text-sm text-muted-foreground">/mo</span>
                )}
              </div>

              <div className="space-y-2">
                {Object.entries(features).map(([key, val]) => (
                  <div key={key} className="flex items-center gap-2 text-sm">
                    <Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span className="text-muted-foreground capitalize">
                      {String(val)} {key}
                    </span>
                  </div>
                ))}
              </div>

              <div className="pt-2">
                {isCurrent ? (
                  <Button variant="outline" className="w-full" disabled>
                    Current Plan
                  </Button>
                ) : plan.name === "custom" || plan.name === "enterprise" ? (
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={() =>
                      window.open("mailto:sales@aricatech.com?subject=Enterprise%20Plan%20Inquiry", "_blank")
                    }
                  >
                    Contact Sales <ArrowRight className="h-4 w-4 ml-1" />
                  </Button>
                ) : (
                  <Button
                    className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
                    disabled={checkoutMutation.isPending}
                    onClick={() => checkoutMutation.mutate({ planId: plan.id || plan.name, billingCycle: "monthly" })}
                  >
                    {checkoutMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                    ) : (
                      <Zap className="h-4 w-4 mr-1" />
                    )}
                    Upgrade
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function InvoicesSection() {
  const { data: invoicesData, isLoading } = useQuery({
    queryKey: ["/api/billing/invoices"],
  });

  const invoicesList = ((invoicesData as any)?.data || invoicesData || []) as any[];

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-12" />
        <Skeleton className="h-12" />
        <Skeleton className="h-12" />
      </div>
    );
  }

  if (invoicesList.length === 0) {
    return (
      <Card className="glass-card border-border/50">
        <CardContent className="p-8 text-center">
          <FileText className="h-10 w-10 text-muted-foreground/40 mx-auto mb-3" />
          <p className="text-muted-foreground">No invoices yet</p>
          <p className="text-xs text-muted-foreground/60 mt-1">Invoices will appear here after your first payment</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-card border-border/50 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm" role="table" aria-label="Invoices">
          <thead>
            <tr className="border-b border-border/50 bg-muted/30">
              <th className="text-left px-4 py-3 font-medium text-muted-foreground">Date</th>
              <th className="text-left px-4 py-3 font-medium text-muted-foreground">Amount</th>
              <th className="text-left px-4 py-3 font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-3 font-medium text-muted-foreground">Period</th>
              <th className="text-right px-4 py-3 font-medium text-muted-foreground">Actions</th>
            </tr>
          </thead>
          <tbody>
            {invoicesList.map((inv: any) => (
              <tr key={inv.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                <td className="px-4 py-3">{formatDate(inv.paidAt || inv.createdAt)}</td>
                <td className="px-4 py-3 font-medium">{formatCents(inv.amountDueCents)}</td>
                <td className="px-4 py-3">{statusBadge(inv.status)}</td>
                <td className="px-4 py-3 text-muted-foreground">
                  {formatDate(inv.periodStart)} — {formatDate(inv.periodEnd)}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-1">
                    {inv.pdfUrl && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2"
                        onClick={() => window.open(inv.pdfUrl, "_blank")}
                        aria-label="Download PDF"
                      >
                        <Download className="h-3.5 w-3.5" />
                      </Button>
                    )}
                    {inv.hostedUrl && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2"
                        onClick={() => window.open(inv.hostedUrl, "_blank")}
                        aria-label="View invoice"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function PaymentMethodSection() {
  const { data: subData } = useQuery({
    queryKey: ["/api/billing/subscription"],
  });
  const { toast } = useToast();
  const sub = (subData as any)?.data || subData;
  const hasStripe = !!sub?.subscription?.stripeCustomerId;

  const portalMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/portal-session", {
        returnUrl: window.location.href,
      });
      return res.json();
    },
    onSuccess: (data: any) => {
      const url = data?.data?.url || data?.url;
      if (url) {
        window.location.href = url;
      } else {
        toast({
          title: "Portal not available",
          description: "Stripe Customer Portal is not configured.",
          variant: "default",
        });
      }
    },
    onError: (err: Error) => {
      toast({ title: "Failed to open portal", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Card className="glass-card border-border/50">
      <CardHeader>
        <div className="flex items-center gap-2">
          <CreditCard className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-base">Payment Method</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {hasStripe ? (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-muted/50">
                <CreditCard className="h-5 w-5 text-muted-foreground" />
              </div>
              <div>
                <p className="text-sm font-medium">Card on file</p>
                <p className="text-xs text-muted-foreground">Managed through Stripe Customer Portal</p>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => portalMutation.mutate()}
              disabled={portalMutation.isPending}
            >
              {portalMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Manage"}
            </Button>
          </div>
        ) : (
          <div className="text-center py-4">
            <CreditCard className="h-8 w-8 text-muted-foreground/40 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">No payment method on file</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              Add a payment method when you upgrade to a paid plan
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function DangerZoneSection() {
  const { data: subData, refetch } = useQuery({
    queryKey: ["/api/billing/subscription"],
  });
  const { toast } = useToast();
  const [showCancel, setShowCancel] = useState(false);
  const [cancelReason, setCancelReason] = useState("");

  const sub = (subData as any)?.data || subData;
  const subscription = sub?.subscription;
  const isFreePlan = sub?.isFreePlan !== false;
  const isCancelled = subscription?.cancelledAt !== null && subscription?.cancelledAt !== undefined;

  const cancelMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/cancel", {
        reason: cancelReason || "user_requested",
        immediate: false,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({
        title: "Subscription cancelled",
        description: "You'll retain access until the end of your billing period.",
      });
      setShowCancel(false);
      refetch();
    },
    onError: (err: Error) => {
      toast({ title: "Cancellation failed", description: err.message, variant: "destructive" });
    },
  });

  const reactivateMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/reactivate", {});
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Subscription reactivated", description: "Your subscription has been reactivated." });
      refetch();
    },
    onError: (err: Error) => {
      toast({ title: "Reactivation failed", description: err.message, variant: "destructive" });
    },
  });

  if (isFreePlan) return null;

  return (
    <Card className="glass-card border-red-500/20">
      <CardHeader>
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-red-400" />
          <CardTitle className="text-base text-red-400">Danger Zone</CardTitle>
        </div>
        <CardDescription>
          {isCancelled
            ? "Your subscription is set to cancel at the end of the billing period."
            : "Cancelling your subscription will downgrade you to the Free plan."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isCancelled ? (
          <Button
            variant="outline"
            className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
            disabled={reactivateMutation.isPending}
            onClick={() => reactivateMutation.mutate()}
          >
            {reactivateMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            Reactivate Subscription
          </Button>
        ) : showCancel ? (
          <div className="space-y-3">
            <textarea
              className="w-full rounded-md border border-border/50 bg-background/50 px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              placeholder="Why are you cancelling? (optional)"
              rows={3}
              value={cancelReason}
              onChange={(e) => setCancelReason(e.target.value)}
            />
            <div className="flex items-center gap-2">
              <Button
                variant="destructive"
                size="sm"
                disabled={cancelMutation.isPending}
                onClick={() => cancelMutation.mutate()}
              >
                {cancelMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                Confirm Cancellation
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setShowCancel(false)}>
                Keep Subscription
              </Button>
            </div>
          </div>
        ) : (
          <Button
            variant="outline"
            className="border-red-500/30 text-red-400 hover:bg-red-500/10"
            onClick={() => setShowCancel(true)}
          >
            Cancel Subscription
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export default function BillingPage() {
  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Subscription & Billing</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Manage your subscription, view invoices, and update payment methods
          </p>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="plans">Plans</TabsTrigger>
          <TabsTrigger value="invoices">Invoices</TabsTrigger>
          <TabsTrigger value="payment">Payment</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <CurrentPlanSection />
          <DangerZoneSection />
        </TabsContent>

        <TabsContent value="plans">
          <PlanComparisonSection />
        </TabsContent>

        <TabsContent value="invoices">
          <InvoicesSection />
        </TabsContent>

        <TabsContent value="payment" className="space-y-4">
          <PaymentMethodSection />
          <DangerZoneSection />
        </TabsContent>
      </Tabs>
    </div>
  );
}
