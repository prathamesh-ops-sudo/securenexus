import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Building2,
  Users,
  ShieldAlert,
  DollarSign,
  Activity,
  ScrollText,
  HeartPulse,
  Search,
  UserX,
  UserCheck,
  Eye,
  KeyRound,
  ChevronLeft,
  ChevronRight,
  TrendingUp,
  BarChart3,
  Globe,
  Clock,
  AlertTriangle,
} from "lucide-react";

type AdminTab = "overview" | "organizations" | "users" | "subscriptions" | "revenue" | "audit" | "health";

interface PlatformStats {
  totalOrgs: number;
  totalUsers: number;
  totalAlerts: number;
  totalIncidents: number;
  activeSubscriptions: number;
  mrr: number;
  newOrgsThisMonth: number;
  newUsersThisMonth: number;
}

interface OrgListItem {
  id: string;
  name: string;
  slug: string;
  industry: string | null;
  createdAt: string;
  deletedAt: string | null;
  memberCount: number;
  alertCount: number;
  subscription: { status: string } | null;
  plan: { name: string } | null;
}

interface UserListItem {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  isSuperAdmin: boolean;
  disabledAt: string | null;
  lastLoginAt: string | null;
  createdAt: string;
  organizations: { orgId: string; orgName: string; role: string; status: string }[];
}

interface SubscriptionListItem {
  id: string;
  orgId: string;
  orgName: string;
  planName: string;
  planPriceMonthly: number | null;
  status: string;
  billingCycle: string;
  currentPeriodEnd: string | null;
}

interface RevenueData {
  mrr: number;
  arr: number;
  planDistribution: {
    planName: string;
    count: number;
    monthlyPriceCents: number | null;
    annualPriceCents: number | null;
    billingCycle: string;
  }[];
  churnRate: number;
  totalSubscriptions: number;
  cancelledSubscriptions: number;
}

interface AuditLogEntry {
  id: string;
  orgId: string | null;
  userId: string | null;
  userName: string | null;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  createdAt: string;
}

interface HealthData {
  rds: { status: string; latencyMs: number; pool: Record<string, unknown> };
  application: { status: string; uptime: number; memoryUsage: Record<string, number>; nodeVersion: string };
  timestamp: string;
}

function StatCard({
  title,
  value,
  icon: Icon,
  subtitle,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  subtitle?: string;
}) {
  return (
    <Card className="glass-card border-border/40">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">{title}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
            {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
          </div>
          <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
            <Icon className="h-5 w-5 text-primary" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function OverviewTab() {
  const { data, isLoading } = useQuery<PlatformStats>({
    queryKey: ["/api/platform-admin/stats"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/platform-admin/stats");
      const body = await res.json();
      return body.data;
    },
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    );
  }

  if (!data) {
    return <p className="text-muted-foreground text-center py-8">Failed to load platform stats</p>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Organizations"
          value={data.totalOrgs}
          icon={Building2}
          subtitle={`+${data.newOrgsThisMonth} this month`}
        />
        <StatCard
          title="Total Users"
          value={data.totalUsers}
          icon={Users}
          subtitle={`+${data.newUsersThisMonth} this month`}
        />
        <StatCard title="Total Alerts" value={data.totalAlerts.toLocaleString()} icon={ShieldAlert} />
        <StatCard title="Active Subscriptions" value={data.activeSubscriptions} icon={DollarSign} />
        <StatCard title="MRR" value={`$${(data.mrr / 100).toLocaleString()}`} icon={TrendingUp} />
        <StatCard title="Total Incidents" value={data.totalIncidents} icon={AlertTriangle} />
        <StatCard title="New Orgs (30d)" value={data.newOrgsThisMonth} icon={Globe} />
        <StatCard title="New Users (30d)" value={data.newUsersThisMonth} icon={Users} />
      </div>
    </div>
  );
}

function OrganizationsTab() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const limit = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["/api/platform-admin/organizations", search, page],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) });
      if (search) params.set("search", search);
      const res = await apiRequest("GET", `/api/platform-admin/organizations?${params}`);
      const body = await res.json();
      return { items: body.data as OrgListItem[], total: body.meta?.total ?? 0 };
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search organizations..."
            className="pl-9"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </div>
      ) : !data?.items.length ? (
        <Card className="glass-card border-border/40">
          <CardContent className="py-8 text-center text-muted-foreground">
            <Building2 className="h-10 w-10 mx-auto mb-2 opacity-40" />
            <p>No organizations found</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="text-left p-3 font-medium">Name</th>
                  <th className="text-left p-3 font-medium">Plan</th>
                  <th className="text-left p-3 font-medium">Status</th>
                  <th className="text-right p-3 font-medium">Members</th>
                  <th className="text-right p-3 font-medium">Alerts</th>
                  <th className="text-left p-3 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((org) => (
                  <tr key={org.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="p-3">
                      <div className="font-medium">{org.name}</div>
                      <div className="text-xs text-muted-foreground">{org.slug}</div>
                    </td>
                    <td className="p-3">
                      <Badge variant="outline" className="text-xs">
                        {org.plan?.name ?? "Free"}
                      </Badge>
                    </td>
                    <td className="p-3">
                      <Badge variant={org.deletedAt ? "destructive" : "default"} className="text-xs">
                        {org.deletedAt ? "Suspended" : "Active"}
                      </Badge>
                    </td>
                    <td className="p-3 text-right">{org.memberCount}</td>
                    <td className="p-3 text-right">{org.alertCount.toLocaleString()}</td>
                    <td className="p-3 text-xs text-muted-foreground">
                      {new Date(org.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {page * limit + 1}-{Math.min((page + 1) * limit, data.total)} of {data.total}
            </p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={(page + 1) * limit >= data.total}
                onClick={() => setPage(page + 1)}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function UsersTab() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const limit = 20;
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ["/api/platform-admin/users", search, page],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) });
      if (search) params.set("search", search);
      const res = await apiRequest("GET", `/api/platform-admin/users?${params}`);
      const body = await res.json();
      return { items: body.data as UserListItem[], total: body.meta?.total ?? 0 };
    },
  });

  const disableMutation = useMutation({
    mutationFn: async (userId: string) => {
      await apiRequest("POST", `/api/platform-admin/users/${userId}/disable`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/platform-admin/users"] });
      toast({ title: "User disabled" });
    },
    onError: () => toast({ title: "Failed to disable user", variant: "destructive" }),
  });

  const enableMutation = useMutation({
    mutationFn: async (userId: string) => {
      await apiRequest("POST", `/api/platform-admin/users/${userId}/enable`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/platform-admin/users"] });
      toast({ title: "User enabled" });
    },
    onError: () => toast({ title: "Failed to enable user", variant: "destructive" }),
  });

  const resetMutation = useMutation({
    mutationFn: async (userId: string) => {
      await apiRequest("POST", `/api/platform-admin/users/${userId}/force-password-reset`);
    },
    onSuccess: () => toast({ title: "Password reset forced" }),
    onError: () => toast({ title: "Failed to force password reset", variant: "destructive" }),
  });

  const impersonateMutation = useMutation({
    mutationFn: async (userId: string) => {
      const res = await apiRequest("POST", `/api/platform-admin/impersonate/${userId}`);
      const body = await res.json();
      return body.data;
    },
    onSuccess: (data: { impersonationToken: string; targetUser: { email: string }; expiresAt: string }) => {
      sessionStorage.setItem("impersonationToken", data.impersonationToken);
      sessionStorage.setItem("impersonatingAs", data.targetUser.email);
      sessionStorage.setItem("impersonationExpires", data.expiresAt);
      toast({ title: `Impersonating ${data.targetUser.email}` });
      window.location.reload();
    },
    onError: () => toast({ title: "Failed to start impersonation", variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search users..."
            className="pl-9"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </div>
      ) : !data?.items.length ? (
        <Card className="glass-card border-border/40">
          <CardContent className="py-8 text-center text-muted-foreground">
            <Users className="h-10 w-10 mx-auto mb-2 opacity-40" />
            <p>No users found</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="text-left p-3 font-medium">User</th>
                  <th className="text-left p-3 font-medium">Organizations</th>
                  <th className="text-left p-3 font-medium">Status</th>
                  <th className="text-left p-3 font-medium">Last Login</th>
                  <th className="text-right p-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((user) => (
                  <tr key={user.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="p-3">
                      <div className="font-medium">
                        {user.firstName || user.lastName
                          ? `${user.firstName ?? ""} ${user.lastName ?? ""}`.trim()
                          : "—"}
                        {user.isSuperAdmin && (
                          <Badge variant="outline" className="ml-2 text-xs border-yellow-500/50 text-yellow-500">
                            Admin
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">{user.email}</div>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {user.organizations.length > 0 ? (
                          user.organizations.slice(0, 3).map((o) => (
                            <Badge key={o.orgId} variant="secondary" className="text-xs">
                              {o.orgName}
                            </Badge>
                          ))
                        ) : (
                          <span className="text-xs text-muted-foreground">No org</span>
                        )}
                        {user.organizations.length > 3 && (
                          <Badge variant="secondary" className="text-xs">
                            +{user.organizations.length - 3}
                          </Badge>
                        )}
                      </div>
                    </td>
                    <td className="p-3">
                      <Badge variant={user.disabledAt ? "destructive" : "default"} className="text-xs">
                        {user.disabledAt ? "Disabled" : "Active"}
                      </Badge>
                    </td>
                    <td className="p-3 text-xs text-muted-foreground">
                      {user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : "Never"}
                    </td>
                    <td className="p-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        {!user.isSuperAdmin && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-xs"
                            onClick={() => impersonateMutation.mutate(user.id)}
                            disabled={!!user.disabledAt || impersonateMutation.isPending}
                            title="Impersonate"
                          >
                            <Eye className="h-3 w-3" />
                          </Button>
                        )}
                        {user.disabledAt ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-xs text-green-500"
                            onClick={() => enableMutation.mutate(user.id)}
                            disabled={enableMutation.isPending}
                            title="Enable"
                          >
                            <UserCheck className="h-3 w-3" />
                          </Button>
                        ) : !user.isSuperAdmin ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-xs text-destructive"
                            onClick={() => disableMutation.mutate(user.id)}
                            disabled={disableMutation.isPending}
                            title="Disable"
                          >
                            <UserX className="h-3 w-3" />
                          </Button>
                        ) : null}
                        {!user.isSuperAdmin && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-xs"
                            onClick={() => resetMutation.mutate(user.id)}
                            disabled={resetMutation.isPending}
                            title="Force Password Reset"
                          >
                            <KeyRound className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {page * limit + 1}-{Math.min((page + 1) * limit, data.total)} of {data.total}
            </p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={(page + 1) * limit >= data.total}
                onClick={() => setPage(page + 1)}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function SubscriptionsTab() {
  const [page, setPage] = useState(0);
  const limit = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["/api/platform-admin/subscriptions", page],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) });
      const res = await apiRequest("GET", `/api/platform-admin/subscriptions?${params}`);
      const body = await res.json();
      return { items: body.data as SubscriptionListItem[], total: body.meta?.total ?? 0 };
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14" />
        ))}
      </div>
    );
  }

  if (!data?.items.length) {
    return (
      <Card className="glass-card border-border/40">
        <CardContent className="py-8 text-center text-muted-foreground">
          <DollarSign className="h-10 w-10 mx-auto mb-2 opacity-40" />
          <p>No subscriptions found</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border/40 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/40 bg-muted/30">
              <th className="text-left p-3 font-medium">Organization</th>
              <th className="text-left p-3 font-medium">Plan</th>
              <th className="text-left p-3 font-medium">Status</th>
              <th className="text-left p-3 font-medium">Cycle</th>
              <th className="text-right p-3 font-medium">Monthly</th>
              <th className="text-left p-3 font-medium">Renewal</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((sub) => (
              <tr key={sub.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                <td className="p-3 font-medium">{sub.orgName}</td>
                <td className="p-3">
                  <Badge variant="outline" className="text-xs">
                    {sub.planName}
                  </Badge>
                </td>
                <td className="p-3">
                  <Badge
                    variant={
                      sub.status === "active" ? "default" : sub.status === "cancelled" ? "destructive" : "secondary"
                    }
                    className="text-xs"
                  >
                    {sub.status}
                  </Badge>
                </td>
                <td className="p-3 text-xs">{sub.billingCycle}</td>
                <td className="p-3 text-right">${((sub.planPriceMonthly ?? 0) / 100).toFixed(2)}</td>
                <td className="p-3 text-xs text-muted-foreground">
                  {sub.currentPeriodEnd ? new Date(sub.currentPeriodEnd).toLocaleDateString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Showing {page * limit + 1}-{Math.min((page + 1) * limit, data.total)} of {data.total}
        </p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={(page + 1) * limit >= data.total}
            onClick={() => setPage(page + 1)}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

function RevenueTab() {
  const { data, isLoading } = useQuery<RevenueData>({
    queryKey: ["/api/platform-admin/revenue"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/platform-admin/revenue");
      const body = await res.json();
      return body.data;
    },
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    );
  }

  if (!data) {
    return <p className="text-muted-foreground text-center py-8">Failed to load revenue data</p>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard title="Monthly Recurring Revenue" value={`$${(data.mrr / 100).toLocaleString()}`} icon={DollarSign} />
        <StatCard title="Annual Run Rate" value={`$${(data.arr / 100).toLocaleString()}`} icon={TrendingUp} />
        <StatCard title="Churn Rate" value={`${data.churnRate}%`} icon={BarChart3} />
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader>
          <CardTitle className="text-base">Plan Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          {data.planDistribution.length === 0 ? (
            <p className="text-muted-foreground text-center py-4">No active subscriptions</p>
          ) : (
            <div className="space-y-3">
              {data.planDistribution.map((plan) => {
                const maxCount = Math.max(...data.planDistribution.map((p) => p.count));
                const pct = maxCount > 0 ? (plan.count / maxCount) * 100 : 0;
                return (
                  <div key={`${plan.planName}-${plan.billingCycle}`} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium">{plan.planName}</span>
                      <span className="text-muted-foreground">
                        {plan.count} subs &middot; $
                        {(
                          (plan.billingCycle === "annual"
                            ? Math.round((plan.annualPriceCents ?? 0) / 12)
                            : (plan.monthlyPriceCents ?? 0)) / 100
                        ).toFixed(0)}
                        /mo each
                      </span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <StatCard title="Total Subscriptions" value={data.totalSubscriptions} icon={DollarSign} />
        <StatCard title="Cancelled" value={data.cancelledSubscriptions} icon={UserX} />
      </div>
    </div>
  );
}

function AuditLogTab() {
  const [page, setPage] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const limit = 30;

  const { data, isLoading } = useQuery({
    queryKey: ["/api/platform-admin/audit-logs", page, actionFilter],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) });
      if (actionFilter) params.set("action", actionFilter);
      const res = await apiRequest("GET", `/api/platform-admin/audit-logs?${params}`);
      const body = await res.json();
      return { items: body.data as AuditLogEntry[], total: body.meta?.total ?? 0 };
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filter by action..."
            className="pl-9"
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setPage(0);
            }}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      ) : !data?.items.length ? (
        <Card className="glass-card border-border/40">
          <CardContent className="py-8 text-center text-muted-foreground">
            <ScrollText className="h-10 w-10 mx-auto mb-2 opacity-40" />
            <p>No audit log entries found</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="text-left p-3 font-medium">Timestamp</th>
                  <th className="text-left p-3 font-medium">User</th>
                  <th className="text-left p-3 font-medium">Action</th>
                  <th className="text-left p-3 font-medium">Resource</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((entry) => (
                  <tr key={entry.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="p-3 text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(entry.createdAt).toLocaleString()}
                    </td>
                    <td className="p-3 text-xs">{entry.userName ?? entry.userId ?? "—"}</td>
                    <td className="p-3">
                      <Badge variant="outline" className="text-xs font-mono">
                        {entry.action}
                      </Badge>
                    </td>
                    <td className="p-3 text-xs text-muted-foreground">
                      {entry.resourceType ? `${entry.resourceType}/${entry.resourceId ?? ""}` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {page * limit + 1}-{Math.min((page + 1) * limit, data.total)} of {data.total}
            </p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={(page + 1) * limit >= data.total}
                onClick={() => setPage(page + 1)}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function HealthTab() {
  const { data, isLoading, refetch } = useQuery<HealthData>({
    queryKey: ["/api/platform-admin/health"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/platform-admin/health");
      const body = await res.json();
      return body.data;
    },
    refetchInterval: 30000,
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-40" />
        ))}
      </div>
    );
  }

  if (!data) {
    return <p className="text-muted-foreground text-center py-8">Failed to load health data</p>;
  }

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">Last checked: {new Date(data.timestamp).toLocaleString()}</p>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="h-4 w-4" />
              RDS (PostgreSQL)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center gap-2">
              <div
                className={`h-3 w-3 rounded-full ${data.rds.status === "healthy" ? "bg-green-500" : "bg-red-500"}`}
              />
              <span className="text-sm font-medium capitalize">{data.rds.status}</span>
            </div>
            <div className="text-xs text-muted-foreground space-y-1">
              <p>Latency: {data.rds.latencyMs}ms</p>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card border-border/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <HeartPulse className="h-4 w-4" />
              Application
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center gap-2">
              <div
                className={`h-3 w-3 rounded-full ${data.application.status === "healthy" ? "bg-green-500" : "bg-red-500"}`}
              />
              <span className="text-sm font-medium capitalize">{data.application.status}</span>
            </div>
            <div className="text-xs text-muted-foreground space-y-1">
              <p>Uptime: {formatUptime(data.application.uptime)}</p>
              <p>Node: {data.application.nodeVersion}</p>
              <p>
                Heap: {formatBytes(data.application.memoryUsage.heapUsed ?? 0)} /{" "}
                {formatBytes(data.application.memoryUsage.heapTotal ?? 0)}
              </p>
              <p>RSS: {formatBytes(data.application.memoryUsage.rss ?? 0)}</p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

const TABS: { id: AdminTab; label: string; icon: React.ElementType }[] = [
  { id: "overview", label: "Overview", icon: BarChart3 },
  { id: "organizations", label: "Organizations", icon: Building2 },
  { id: "users", label: "Users", icon: Users },
  { id: "subscriptions", label: "Subscriptions", icon: DollarSign },
  { id: "revenue", label: "Revenue", icon: TrendingUp },
  { id: "audit", label: "Audit Log", icon: ScrollText },
  { id: "health", label: "Health", icon: HeartPulse },
];

export default function PlatformAdminPage() {
  const [activeTab, setActiveTab] = useState<AdminTab>("overview");
  const { user } = useAuth();

  if (!user?.isSuperAdmin) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="glass-card border-border/40 max-w-md">
          <CardContent className="py-8 text-center">
            <ShieldAlert className="h-12 w-12 mx-auto mb-3 text-destructive opacity-60" />
            <h2 className="text-lg font-semibold">Access Denied</h2>
            <p className="text-sm text-muted-foreground mt-1">
              Platform super-admin access is required to view this page.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Platform Administration</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage organizations, users, subscriptions, and platform health
        </p>
      </div>

      <div className="flex items-center gap-1 border-b border-border/40 overflow-x-auto pb-px">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-t-md transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? "text-primary border-b-2 border-primary bg-primary/5"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      <div>
        {activeTab === "overview" && <OverviewTab />}
        {activeTab === "organizations" && <OrganizationsTab />}
        {activeTab === "users" && <UsersTab />}
        {activeTab === "subscriptions" && <SubscriptionsTab />}
        {activeTab === "revenue" && <RevenueTab />}
        {activeTab === "audit" && <AuditLogTab />}
        {activeTab === "health" && <HealthTab />}
      </div>
    </div>
  );
}
