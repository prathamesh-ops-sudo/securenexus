import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useOrgContext } from "@/hooks/use-org-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Building2,
  AlertTriangle,
  Shield,
  Plug,
  FileWarning,
  Plus,
  UserPlus,
  Trash2,
  BarChart3,
  ExternalLink,
  RefreshCw,
} from "lucide-react";

interface ChildOrg {
  id: string;
  name: string;
  slug: string;
  industry: string | null;
  contactEmail: string | null;
  orgType: string;
  createdAt: string;
}

interface MsspGrant {
  id: string;
  parentOrgId: string;
  childOrgId: string;
  grantedRole: string;
  scope: Record<string, string[]>;
  grantedBy: string;
  grantedAt: string;
  revokedAt: string | null;
}

interface MsspStats {
  parentOrgId: string;
  childCount: number;
  totalAlerts: number;
  criticalAlerts: number;
  openIncidents: number;
  totalConnectors: number;
  perOrg: {
    orgId: string;
    orgName: string;
    alertCount: number;
    incidentCount: number;
    connectorCount: number;
  }[];
}

function StatCard({
  title,
  value,
  icon: Icon,
  variant = "default",
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  variant?: "default" | "critical" | "warning" | "success";
}) {
  const colorMap = {
    default: "text-cyan-400",
    critical: "text-red-400",
    warning: "text-amber-400",
    success: "text-emerald-400",
  };
  return (
    <Card className="glass-subtle hover:glass-strong transition-all duration-200">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground font-medium">{title}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
          </div>
          <div className={`p-2 rounded-lg bg-background/50 ${colorMap[variant]}`}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatsSkeletons() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {Array.from({ length: 5 }).map((_, i) => (
        <Card key={`stat-skeleton-${i}`} className="glass-subtle">
          <CardContent className="p-4">
            <Skeleton className="h-3 w-20 mb-2" />
            <Skeleton className="h-8 w-16" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function CreateChildOrgDialog({ onCreated }: { onCreated: () => void }) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [industry, setIndustry] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [open, setOpen] = useState(false);

  const createMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = { name, slug };
      if (industry) body.industry = industry;
      if (contactEmail) body.contactEmail = contactEmail;
      await apiRequest("POST", "/api/mssp/children", body);
    },
    onSuccess: () => {
      toast({ title: "Client organization created" });
      setName("");
      setSlug("");
      setIndustry("");
      setContactEmail("");
      setOpen(false);
      onCreated();
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create client org", description: err.message, variant: "destructive" });
    },
  });

  const handleNameChange = (val: string) => {
    setName(val);
    setSlug(
      val
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, "")
        .replace(/\s+/g, "-")
        .slice(0, 60),
    );
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-1.5">
          <Plus className="h-4 w-4" />
          Add Client Org
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Client Organization</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="child-name">Organization Name</Label>
            <Input
              id="child-name"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="Acme Security Corp"
              maxLength={100}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="child-slug">Slug</Label>
            <Input
              id="child-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="acme-security"
              maxLength={60}
            />
            <p className="text-[10px] text-muted-foreground">Lowercase alphanumeric with hyphens only</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="child-industry">Industry (optional)</Label>
            <Input
              id="child-industry"
              value={industry}
              onChange={(e) => setIndustry(e.target.value)}
              placeholder="Healthcare"
              maxLength={100}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="child-email">Contact Email (optional)</Label>
            <Input
              id="child-email"
              type="email"
              value={contactEmail}
              onChange={(e) => setContactEmail(e.target.value)}
              placeholder="security@acme.com"
              maxLength={255}
            />
          </div>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            onClick={() => createMutation.mutate()}
            disabled={!name.trim() || !slug.trim() || createMutation.isPending}
          >
            {createMutation.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function GrantAccessDialog({ childOrgs, onGranted }: { childOrgs: ChildOrg[]; onGranted: () => void }) {
  const { toast } = useToast();
  const [childOrgId, setChildOrgId] = useState("");
  const [grantedRole, setGrantedRole] = useState("viewer");
  const [open, setOpen] = useState(false);

  const grantMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/mssp/grants", { childOrgId, grantedRole });
    },
    onSuccess: () => {
      toast({ title: "Access granted" });
      setChildOrgId("");
      setGrantedRole("viewer");
      setOpen(false);
      onGranted();
    },
    onError: (err: Error) => {
      toast({ title: "Failed to grant access", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" className="gap-1.5">
          <UserPlus className="h-4 w-4" />
          Grant Access
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Grant MSSP Access</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label>Client Organization</Label>
            <Select value={childOrgId} onValueChange={setChildOrgId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a client org" />
              </SelectTrigger>
              <SelectContent>
                {childOrgs.map((org) => (
                  <SelectItem key={org.id} value={org.id}>
                    {org.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Access Role</Label>
            <Select value={grantedRole} onValueChange={setGrantedRole}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">Viewer</SelectItem>
                <SelectItem value="analyst">Analyst</SelectItem>
                <SelectItem value="manager">Manager</SelectItem>
                <SelectItem value="admin">Admin</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button onClick={() => grantMutation.mutate()} disabled={!childOrgId || grantMutation.isPending}>
            {grantMutation.isPending ? "Granting..." : "Grant Access"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type MsspTab = "overview" | "clients" | "access";

export default function MsspDashboardPage() {
  const [activeTab, setActiveTab] = useState<MsspTab>("overview");
  const { currentOrg } = useOrgContext();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const isMsspParent = currentOrg?.orgType === "mssp_parent";

  const { data: stats, isLoading: statsLoading } = useQuery<MsspStats>({
    queryKey: ["/api/mssp/stats"],
    enabled: isMsspParent,
  });

  const { data: children, isLoading: childrenLoading } = useQuery<ChildOrg[]>({
    queryKey: ["/api/mssp/children"],
    enabled: isMsspParent,
  });

  const { data: grants, isLoading: grantsLoading } = useQuery<MsspGrant[]>({
    queryKey: ["/api/mssp/grants"],
    enabled: isMsspParent,
  });

  const revokeMutation = useMutation({
    mutationFn: async (grantId: string) => {
      await apiRequest("DELETE", `/api/mssp/grants/${grantId}`);
    },
    onSuccess: () => {
      toast({ title: "Access revoked" });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp/grants"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to revoke access", description: err.message, variant: "destructive" });
    },
  });

  const refreshAll = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/mssp/stats"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp/children"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp/grants"] });
  };

  if (!isMsspParent) {
    return (
      <div className="p-6">
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center">
            <Building2 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h2 className="text-lg font-semibold mb-2">MSSP Dashboard</h2>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Your organization is not configured as an MSSP parent. Contact your administrator to enable MSSP features
              for managing multiple client organizations from a single dashboard.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const TABS: { key: MsspTab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "clients", label: "Client Orgs" },
    { key: "access", label: "Access Grants" },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">MSSP Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Manage and monitor your client organizations</p>
        </div>
        <Button variant="outline" size="sm" onClick={refreshAll} className="gap-1.5">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      <div className="flex gap-1 border-b border-border/50 pb-px">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
              activeTab === tab.key
                ? "bg-background border border-b-0 border-border/50 text-foreground"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <div className="space-y-6">
          {statsLoading ? (
            <StatsSkeletons />
          ) : stats ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <StatCard title="Client Orgs" value={stats.childCount} icon={Building2} />
              <StatCard title="Total Alerts" value={stats.totalAlerts} icon={AlertTriangle} variant="warning" />
              <StatCard title="Critical Alerts" value={stats.criticalAlerts} icon={Shield} variant="critical" />
              <StatCard title="Open Incidents" value={stats.openIncidents} icon={FileWarning} variant="warning" />
              <StatCard title="Connectors" value={stats.totalConnectors} icon={Plug} variant="success" />
            </div>
          ) : (
            <Card className="glass-subtle">
              <CardContent className="p-6 text-center text-sm text-muted-foreground">
                No stats available. Add client organizations to see aggregated metrics.
              </CardContent>
            </Card>
          )}

          <Card className="glass-subtle">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-cyan-400" />
                Per-Client Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent>
              {statsLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={`row-skeleton-${i}`} className="h-12 w-full" />
                  ))}
                </div>
              ) : stats?.perOrg && stats.perOrg.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm" role="table">
                    <thead>
                      <tr className="border-b border-border/50 text-muted-foreground">
                        <th className="text-left py-2 px-3 font-medium">Organization</th>
                        <th className="text-right py-2 px-3 font-medium">Alerts</th>
                        <th className="text-right py-2 px-3 font-medium">Incidents</th>
                        <th className="text-right py-2 px-3 font-medium">Connectors</th>
                        <th className="text-right py-2 px-3 font-medium">Health</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.perOrg.map((org) => {
                        const healthScore =
                          org.alertCount === 0 && org.incidentCount === 0
                            ? "healthy"
                            : org.incidentCount > 5
                              ? "critical"
                              : org.incidentCount > 0
                                ? "warning"
                                : "good";
                        const healthBadge = {
                          healthy: (
                            <Badge variant="outline" className="text-emerald-400 border-emerald-400/30">
                              Healthy
                            </Badge>
                          ),
                          good: (
                            <Badge variant="outline" className="text-cyan-400 border-cyan-400/30">
                              Good
                            </Badge>
                          ),
                          warning: (
                            <Badge variant="outline" className="text-amber-400 border-amber-400/30">
                              Warning
                            </Badge>
                          ),
                          critical: (
                            <Badge variant="outline" className="text-red-400 border-red-400/30">
                              Critical
                            </Badge>
                          ),
                        };
                        return (
                          <tr key={org.orgId} className="border-b border-border/30 hover:bg-muted/30 transition-colors">
                            <td className="py-2.5 px-3 font-medium">{org.orgName}</td>
                            <td className="py-2.5 px-3 text-right tabular-nums">{org.alertCount}</td>
                            <td className="py-2.5 px-3 text-right tabular-nums">{org.incidentCount}</td>
                            <td className="py-2.5 px-3 text-right tabular-nums">{org.connectorCount}</td>
                            <td className="py-2.5 px-3 text-right">{healthBadge[healthScore]}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No client organizations yet. Create one to see per-client metrics.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === "clients" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Client Organizations</h2>
            <CreateChildOrgDialog onCreated={refreshAll} />
          </div>

          {childrenLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={`child-skeleton-${i}`} className="h-20 w-full" />
              ))}
            </div>
          ) : children && children.length > 0 ? (
            <div className="grid gap-3">
              {children.map((child) => (
                <Card key={child.id} className="glass-subtle hover:glass-strong transition-all duration-200">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-cyan-500/10">
                          <Building2 className="h-5 w-5 text-cyan-400" />
                        </div>
                        <div>
                          <p className="font-medium">{child.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {child.slug} {child.industry ? `· ${child.industry}` : ""}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">
                          {child.orgType}
                        </Badge>
                        <Button variant="ghost" size="sm" className="gap-1 text-xs" asChild>
                          <a href={`/?org=${child.id}`}>
                            <ExternalLink className="h-3.5 w-3.5" />
                            Switch
                          </a>
                        </Button>
                      </div>
                    </div>
                    {child.contactEmail && (
                      <p className="text-xs text-muted-foreground mt-2 ml-12">{child.contactEmail}</p>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card className="glass-subtle">
              <CardContent className="p-8 text-center">
                <Building2 className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
                <p className="text-sm text-muted-foreground">
                  No client organizations yet. Click "Add Client Org" to create one.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {activeTab === "access" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Access Grants</h2>
            {children && children.length > 0 && <GrantAccessDialog childOrgs={children} onGranted={refreshAll} />}
          </div>

          {grantsLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={`grant-skeleton-${i}`} className="h-16 w-full" />
              ))}
            </div>
          ) : grants && grants.length > 0 ? (
            <div className="grid gap-3">
              {grants.map((grant) => {
                const childOrg = children?.find((c) => c.id === grant.childOrgId);
                return (
                  <Card key={grant.id} className="glass-subtle hover:glass-strong transition-all duration-200">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-emerald-500/10">
                            <UserPlus className="h-5 w-5 text-emerald-400" />
                          </div>
                          <div>
                            <p className="font-medium">{childOrg?.name || grant.childOrgId}</p>
                            <p className="text-xs text-muted-foreground">
                              Role: <span className="font-medium">{grant.grantedRole}</span> · Granted{" "}
                              {new Date(grant.grantedAt).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-red-400 hover:text-red-300 hover:bg-red-400/10 gap-1"
                          onClick={() => revokeMutation.mutate(grant.id)}
                          disabled={revokeMutation.isPending}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Revoke
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ) : (
            <Card className="glass-subtle">
              <CardContent className="p-8 text-center">
                <UserPlus className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
                <p className="text-sm text-muted-foreground">
                  No active access grants. Grant your MSSP team access to client organizations.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
