import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  Package,
  GitBranch,
  Settings,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ChevronRight,
  Search,
  Filter,
  Play,
  Pause,
  XCircle,
  ArrowUpDown,
  BookOpen,
  Layers,
  Target,
  Brain,
  Scale,
  Lock,
  Users,
  FileCheck2,
  Send,
  Eye,
  History,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

function unwrap(data: unknown): any {
  if (data && typeof data === "object" && "data" in data) {
    return (data as any).data;
  }
  return data;
}

const TABS = [
  { id: "overview", label: "Overview", icon: Package },
  { id: "catalog", label: "Pack Catalog", icon: BookOpen },
  { id: "activations", label: "My Activations", icon: CheckCircle2 },
  { id: "changelog", label: "Changelogs", icon: GitBranch },
  { id: "presets", label: "Strictness Presets", icon: ArrowUpDown },
  /* 82.3 — acknowledgment tracking tab */
  { id: "acknowledgments", label: "Acknowledgments", icon: FileCheck2 },
  /* 82.6 — distribution tab */
  { id: "distribution", label: "Distribution", icon: Send },
] as const;

type TabId = (typeof TABS)[number]["id"];

const DOMAIN_ICONS: Record<string, typeof Shield> = {
  cloud_posture: Shield,
  identity_risk: Lock,
  appsec: Target,
  ai_runtime_safety: Brain,
  regulated_workflows: Scale,
};

const DOMAIN_COLORS: Record<string, string> = {
  cloud_posture: "text-cyan-400 bg-cyan-400/10 border-cyan-400/30",
  identity_risk: "text-violet-400 bg-violet-400/10 border-violet-400/30",
  appsec: "text-amber-400 bg-amber-400/10 border-amber-400/30",
  ai_runtime_safety: "text-rose-400 bg-rose-400/10 border-rose-400/30",
  regulated_workflows: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30",
};

const STRICTNESS_COLORS: Record<string, string> = {
  starter: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  balanced: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  regulated: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  zero_trust: "bg-red-500/15 text-red-400 border-red-500/30",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400",
  high: "bg-orange-500/15 text-orange-400",
  medium: "bg-amber-500/15 text-amber-400",
  low: "bg-blue-500/15 text-blue-400",
  info: "bg-slate-500/15 text-slate-400",
};

function OverviewTab() {
  const { data: summaryRaw, isLoading: summaryLoading } = useQuery({
    queryKey: ["/api/policy-packs/summary"],
    queryFn: () => apiRequest("GET", "/api/policy-packs/summary").then((r) => r.json()),
  });
  const { data: metaRaw, isLoading: metaLoading } = useQuery({
    queryKey: ["/api/policy-packs/meta"],
    queryFn: () => apiRequest("GET", "/api/policy-packs/meta").then((r) => r.json()),
  });

  const summary = unwrap(summaryRaw);
  const meta = unwrap(metaRaw);
  const isLoading = summaryLoading || metaLoading;

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!summary) {
    return (
      <Card className="glass-subtle">
        <CardContent className="p-8 text-center text-muted-foreground">
          <Package className="h-12 w-12 mx-auto mb-3 opacity-40" />
          <p>No policy pack data available</p>
        </CardContent>
      </Card>
    );
  }

  const domains = meta?.domains || {};
  const presets = meta?.presets || [];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-subtle">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <Package className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.totalPacks}</p>
                <p className="text-xs text-muted-foreground">Policy Packs</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="glass-subtle">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10">
                <Layers className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.totalRules}</p>
                <p className="text-xs text-muted-foreground">Total Rules</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="glass-subtle">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-500/10">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.totalAlerts}</p>
                <p className="text-xs text-muted-foreground">Alert Templates</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="glass-subtle">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-violet-500/10">
                <Target className="h-5 w-5 text-violet-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{Object.keys(summary.byDomain || {}).length}</p>
                <p className="text-xs text-muted-foreground">Security Domains</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="glass-subtle">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Packs by Domain</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(summary.byDomain || {}).map(([domain, count]) => {
              const DomainIcon = DOMAIN_ICONS[domain] || Shield;
              const colorClass = DOMAIN_COLORS[domain] || "text-slate-400 bg-slate-400/10 border-slate-400/30";
              return (
                <div key={domain} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`p-1.5 rounded border ${colorClass}`}>
                      <DomainIcon className="h-3.5 w-3.5" />
                    </div>
                    <span className="text-sm">{domains[domain] || domain}</span>
                  </div>
                  <Badge variant="secondary" className="text-xs">
                    {count as number} pack{(count as number) !== 1 ? "s" : ""}
                  </Badge>
                </div>
              );
            })}
          </CardContent>
        </Card>

        <Card className="glass-subtle">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Strictness Presets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {presets.map((preset: any) => {
              const packCount = summary.byStrictness?.[preset.id] || 0;
              return (
                <div key={preset.id} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-[10px] px-2 ${STRICTNESS_COLORS[preset.id] || ""}`}>
                      {preset.label}
                    </Badge>
                    <span className="text-xs text-muted-foreground truncate max-w-[200px]">{preset.description}</span>
                  </div>
                  <span className="text-xs font-medium">{packCount}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function CatalogTab() {
  const [search, setSearch] = useState("");
  const [domainFilter, setDomainFilter] = useState<string>("all");
  const [strictnessFilter, setStrictnessFilter] = useState<string>("all");
  const [expandedPack, setExpandedPack] = useState<string | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: packsRaw, isLoading } = useQuery({
    queryKey: ["/api/policy-packs"],
    queryFn: () => apiRequest("GET", "/api/policy-packs").then((r) => r.json()),
  });
  const { data: metaRaw } = useQuery({
    queryKey: ["/api/policy-packs/meta"],
    queryFn: () => apiRequest("GET", "/api/policy-packs/meta").then((r) => r.json()),
  });

  const packs: any[] = unwrap(packsRaw) || [];
  const meta = unwrap(metaRaw);
  const domains = meta?.domains || {};

  const activateMutation = useMutation({
    mutationFn: (packId: string) =>
      apiRequest("POST", `/api/policy-packs/${packId}/activate`, {}).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policy-packs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/policy-packs/org/activations"] });
      toast({ title: "Policy pack activated" });
    },
    onError: () => {
      toast({ title: "Failed to activate pack", variant: "destructive" });
    },
  });

  const filtered = packs.filter((p: any) => {
    if (search) {
      const q = search.toLowerCase();
      if (
        !p.name.toLowerCase().includes(q) &&
        !p.description.toLowerCase().includes(q) &&
        !(p.tags || []).some((t: string) => t.toLowerCase().includes(q))
      ) {
        return false;
      }
    }
    if (domainFilter !== "all" && p.domain !== domainFilter) return false;
    if (strictnessFilter !== "all" && p.strictnessPreset !== strictnessFilter) return false;
    return true;
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full" />
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-48" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search packs by name, description, or tags..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex gap-2">
          <select
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            className="px-3 py-2 text-sm rounded-md border bg-background"
          >
            <option value="all">All Domains</option>
            {Object.entries(domains).map(([key, label]) => (
              <option key={key} value={key}>
                {label as string}
              </option>
            ))}
          </select>
          <select
            value={strictnessFilter}
            onChange={(e) => setStrictnessFilter(e.target.value)}
            className="px-3 py-2 text-sm rounded-md border bg-background"
          >
            <option value="all">All Strictness</option>
            <option value="starter">Starter</option>
            <option value="balanced">Balanced</option>
            <option value="regulated">Regulated</option>
            <option value="zero_trust">Zero Trust</option>
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center text-muted-foreground">
            <Filter className="h-10 w-10 mx-auto mb-3 opacity-40" />
            <p>No policy packs match your filters</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filtered.map((pack: any) => {
            const DomainIcon = DOMAIN_ICONS[pack.domain] || Shield;
            const isExpanded = expandedPack === pack.id;
            return (
              <Card key={pack.id} className="glass-subtle">
                <CardContent className="p-0">
                  <button
                    className="w-full text-left p-4 hover:bg-accent/30 transition-colors"
                    onClick={() => setExpandedPack(isExpanded ? null : pack.id)}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 min-w-0">
                        <div className={`p-2 rounded-lg border mt-0.5 ${DOMAIN_COLORS[pack.domain] || ""}`}>
                          <DomainIcon className="h-5 w-5" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <h3 className="font-semibold text-sm">{pack.name}</h3>
                            <Badge variant="outline" className="text-[10px]">
                              v{pack.version}
                            </Badge>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${STRICTNESS_COLORS[pack.strictnessPreset] || ""}`}
                            >
                              {pack.strictnessPreset}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{pack.description}</p>
                          <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                            <span>{pack.rules?.length || 0} rules</span>
                            <span>{pack.alerts?.length || 0} alerts</span>
                            <span>{pack.dashboards?.length || 0} dashboards</span>
                          </div>
                        </div>
                      </div>
                      <ChevronRight
                        className={`h-4 w-4 shrink-0 mt-1 text-muted-foreground transition-transform ${isExpanded ? "rotate-90" : ""}`}
                      />
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="border-t px-4 pb-4 pt-3 space-y-4">
                      <div>
                        <h4 className="text-xs font-medium mb-2 text-muted-foreground uppercase tracking-wider">
                          Rules
                        </h4>
                        <div className="space-y-2">
                          {(pack.rules || []).map((rule: any) => (
                            <div
                              key={rule.id}
                              className="flex items-center justify-between p-2 rounded-md bg-accent/20"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <Badge className={`text-[10px] px-1.5 ${SEVERITY_COLORS[rule.severity] || ""}`}>
                                  {rule.severity}
                                </Badge>
                                <span className="text-xs font-medium truncate">{rule.title}</span>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                {rule.autoRemediate && (
                                  <Badge
                                    variant="outline"
                                    className="text-[9px] text-emerald-400 border-emerald-400/30"
                                  >
                                    auto-fix
                                  </Badge>
                                )}
                                <span
                                  className={`text-[10px] ${rule.enabled ? "text-emerald-400" : "text-muted-foreground"}`}
                                >
                                  {rule.enabled ? "Enabled" : "Disabled"}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div>
                        <h4 className="text-xs font-medium mb-2 text-muted-foreground uppercase tracking-wider">
                          Alert Templates
                        </h4>
                        <div className="space-y-1">
                          {(pack.alerts || []).map((alert: any) => (
                            <div
                              key={alert.id}
                              className="flex items-center justify-between text-xs p-2 rounded-md bg-accent/20"
                            >
                              <div className="flex items-center gap-2">
                                <Badge className={`text-[10px] px-1.5 ${SEVERITY_COLORS[alert.severity] || ""}`}>
                                  {alert.severity}
                                </Badge>
                                <span>{alert.name}</span>
                              </div>
                              <span className="text-muted-foreground">{(alert.channels || []).join(", ")}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div>
                        <h4 className="text-xs font-medium mb-2 text-muted-foreground uppercase tracking-wider">
                          Ownership
                        </h4>
                        <div className="text-xs space-y-1 p-2 rounded-md bg-accent/20">
                          <p>
                            <span className="text-muted-foreground">Default Owner:</span>{" "}
                            {pack.ownership?.defaultOwnerRole}
                          </p>
                          <p>
                            <span className="text-muted-foreground">Escalation:</span>{" "}
                            {(pack.ownership?.escalationPath || []).join(" → ")}
                          </p>
                          <p>
                            <span className="text-muted-foreground">Review Cadence:</span> Every{" "}
                            {pack.ownership?.reviewCadenceDays} days
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 flex-wrap">
                        {(pack.tags || []).map((tag: string) => (
                          <Badge key={tag} variant="outline" className="text-[10px]">
                            {tag}
                          </Badge>
                        ))}
                      </div>

                      {/* 82.2 — customization workflow: show customizable fields */}
                      {pack.customizable && (
                        <div className="p-2 rounded-md bg-cyan-500/5 border border-cyan-500/20">
                          <div className="flex items-center gap-1.5 mb-1">
                            <Settings className="h-3 w-3 text-cyan-400" />
                            <span className="text-xs font-medium text-cyan-400">Customizable</span>
                          </div>
                          <p className="text-[10px] text-muted-foreground">
                            This pack supports rule-level overrides, severity tuning, and custom thresholds.
                          </p>
                        </div>
                      )}

                      {/* 82.4 — version management: version history link */}
                      {pack.previousVersions && pack.previousVersions > 0 && (
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <History className="h-3 w-3" />
                          <span>
                            {pack.previousVersions} previous version{pack.previousVersions > 1 ? "s" : ""} available
                          </span>
                        </div>
                      )}

                      {/* 82.5 — compliance checking indicator */}
                      {pack.complianceFrameworks && pack.complianceFrameworks.length > 0 && (
                        <div className="flex items-center gap-2 flex-wrap">
                          <FileCheck2 className="h-3 w-3 text-emerald-400" />
                          <span className="text-[10px] text-muted-foreground">Compliance:</span>
                          {pack.complianceFrameworks.map((fw: string) => (
                            <Badge
                              key={fw}
                              variant="outline"
                              className="text-[10px] text-emerald-400 border-emerald-400/30"
                            >
                              {fw}
                            </Badge>
                          ))}
                        </div>
                      )}

                      <div className="flex justify-end">
                        <Button
                          size="sm"
                          onClick={() => activateMutation.mutate(pack.id)}
                          disabled={activateMutation.isPending}
                          className="gap-1.5"
                        >
                          <Play className="h-3.5 w-3.5" />
                          Activate Pack
                        </Button>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ActivationsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: activationsRaw, isLoading } = useQuery({
    queryKey: ["/api/policy-packs/org/activations"],
    queryFn: () => apiRequest("GET", "/api/policy-packs/org/activations").then((r) => r.json()),
  });
  const { data: packsRaw } = useQuery({
    queryKey: ["/api/policy-packs"],
    queryFn: () => apiRequest("GET", "/api/policy-packs").then((r) => r.json()),
  });

  const activations: any[] = unwrap(activationsRaw) || [];
  const packs: any[] = unwrap(packsRaw) || [];
  const packMap = new Map(packs.map((p: any) => [p.id, p]));

  const deactivateMutation = useMutation({
    mutationFn: (packId: string) =>
      apiRequest("POST", `/api/policy-packs/${packId}/deactivate`, {}).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policy-packs/org/activations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/policy-packs"] });
      toast({ title: "Policy pack deactivated" });
    },
    onError: () => {
      toast({ title: "Failed to deactivate", variant: "destructive" });
    },
  });

  const toggleStatusMutation = useMutation({
    mutationFn: ({ packId, status }: { packId: string; status: string }) =>
      apiRequest("PATCH", `/api/policy-packs/${packId}/activation`, { status }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policy-packs/org/activations"] });
      toast({ title: "Activation status updated" });
    },
    onError: () => {
      toast({ title: "Failed to update status", variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-32" />
        ))}
      </div>
    );
  }

  if (activations.length === 0) {
    return (
      <Card className="glass-subtle">
        <CardContent className="p-8 text-center text-muted-foreground">
          <SuccessIcon size={48} color="#22c55e" />
          <p className="font-medium">No active policy packs</p>
          <p className="text-xs mt-1">Go to the Pack Catalog tab to activate policy packs for your organization.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {activations.map((activation: any) => {
        const pack = packMap.get(activation.packId);
        const DomainIcon = pack ? DOMAIN_ICONS[pack.domain] || Shield : Shield;
        const statusIcon =
          activation.status === "active" ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
          ) : activation.status === "paused" ? (
            <Pause className="h-3.5 w-3.5 text-amber-400" />
          ) : (
            <Clock className="h-3.5 w-3.5 text-blue-400" />
          );

        return (
          <Card key={activation.packId} className="glass-subtle">
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 min-w-0">
                  <div className={`p-2 rounded-lg border mt-0.5 ${pack ? DOMAIN_COLORS[pack.domain] || "" : ""}`}>
                    <DomainIcon className="h-5 w-5" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-semibold text-sm">{pack?.name || activation.packId}</h3>
                      {pack && (
                        <Badge variant="outline" className="text-[10px]">
                          v{pack.version}
                        </Badge>
                      )}
                      <div className="flex items-center gap-1">
                        {statusIcon}
                        <span className="text-xs capitalize">{activation.status}</span>
                      </div>
                    </div>
                    {pack && <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{pack.description}</p>}
                    <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                      <span>Activated: {new Date(activation.activatedAt).toLocaleDateString()}</span>
                      {activation.strictnessOverride && (
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${STRICTNESS_COLORS[activation.strictnessOverride] || ""}`}
                        >
                          {activation.strictnessOverride} (override)
                        </Badge>
                      )}
                      {Object.keys(activation.ruleOverrides || {}).length > 0 && (
                        <span>{Object.keys(activation.ruleOverrides).length} rule override(s)</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {activation.status === "active" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleStatusMutation.mutate({ packId: activation.packId, status: "paused" })}
                      disabled={toggleStatusMutation.isPending}
                      className="gap-1 text-xs"
                    >
                      <Pause className="h-3 w-3" />
                      Pause
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleStatusMutation.mutate({ packId: activation.packId, status: "active" })}
                      disabled={toggleStatusMutation.isPending}
                      className="gap-1 text-xs"
                    >
                      <Play className="h-3 w-3" />
                      Resume
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => deactivateMutation.mutate(activation.packId)}
                    disabled={deactivateMutation.isPending}
                    className="gap-1 text-xs text-red-400 hover:text-red-300 border-red-400/30"
                  >
                    <XCircle className="h-3 w-3" />
                    Deactivate
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function ChangelogTab() {
  const [selectedPack, setSelectedPack] = useState<string | null>(null);

  const { data: packsRaw, isLoading } = useQuery({
    queryKey: ["/api/policy-packs"],
    queryFn: () => apiRequest("GET", "/api/policy-packs").then((r) => r.json()),
  });

  const packs: any[] = unwrap(packsRaw) || [];

  const { data: changelogRaw, isLoading: clLoading } = useQuery({
    queryKey: ["/api/policy-packs", selectedPack, "changelog"],
    queryFn: () => apiRequest("GET", `/api/policy-packs/${selectedPack}/changelog`).then((r) => r.json()),
    enabled: !!selectedPack,
  });

  const changelog: any[] = unwrap(changelogRaw) || [];

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 flex-wrap">
        {packs.map((pack: any) => (
          <Button
            key={pack.id}
            variant={selectedPack === pack.id ? "default" : "outline"}
            size="sm"
            onClick={() => setSelectedPack(pack.id)}
            className="text-xs"
          >
            {pack.name}
          </Button>
        ))}
      </div>

      {!selectedPack ? (
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center text-muted-foreground">
            <GitBranch className="h-10 w-10 mx-auto mb-3 opacity-40" />
            <p>Select a policy pack above to view its changelog</p>
          </CardContent>
        </Card>
      ) : clLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      ) : changelog.length === 0 ? (
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center text-muted-foreground">
            <p>No changelog entries for this pack</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {changelog.map((entry: any, idx: number) => (
            <Card key={idx} className="glass-subtle">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="text-xs font-mono">
                    v{entry.version}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{entry.date}</span>
                  <span className="text-xs text-muted-foreground">by {entry.author}</span>
                  {entry.breaking && <Badge className="text-[10px] bg-red-500/15 text-red-400">Breaking</Badge>}
                </div>
                <p className="text-sm font-medium mb-2">{entry.summary}</p>
                <ul className="space-y-1 mb-2">
                  {(entry.changes || []).map((change: string, ci: number) => (
                    <li key={ci} className="text-xs text-muted-foreground flex items-start gap-1.5">
                      <span className="text-cyan-400 mt-0.5">-</span>
                      {change}
                    </li>
                  ))}
                </ul>
                {entry.migrationNotes && (
                  <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300">
                    <span className="font-medium">Migration:</span> {entry.migrationNotes}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function PresetsTab() {
  const { data: metaRaw, isLoading } = useQuery({
    queryKey: ["/api/policy-packs/meta"],
    queryFn: () => apiRequest("GET", "/api/policy-packs/meta").then((r) => r.json()),
  });
  const { data: packsRaw } = useQuery({
    queryKey: ["/api/policy-packs"],
    queryFn: () => apiRequest("GET", "/api/policy-packs").then((r) => r.json()),
  });

  const meta = unwrap(metaRaw);
  const packs: any[] = unwrap(packsRaw) || [];
  const presets = meta?.presets || [];

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-32" />
        ))}
      </div>
    );
  }

  const presetOrder = ["starter", "balanced", "regulated", "zero_trust"];
  const presetIcons: Record<string, typeof Shield> = {
    starter: Zap,
    balanced: Settings,
    regulated: Scale,
    zero_trust: Lock,
  };

  return (
    <div className="space-y-4">
      {presetOrder.map((presetId) => {
        const preset = presets.find((p: any) => p.id === presetId);
        if (!preset) return null;
        const PresetIcon = presetIcons[presetId] || Shield;
        const matchingPacks = packs.filter((p: any) => p.strictnessPreset === presetId);
        const colorClass = STRICTNESS_COLORS[presetId] || "";

        return (
          <Card key={presetId} className="glass-subtle">
            <CardContent className="p-5">
              <div className="flex items-start gap-4">
                <div className={`p-3 rounded-lg border ${colorClass}`}>
                  <PresetIcon className="h-6 w-6" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-semibold">{preset.label}</h3>
                    <Badge variant="outline" className={`text-[10px] ${colorClass}`}>
                      {matchingPacks.length} pack{matchingPacks.length !== 1 ? "s" : ""}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3">{preset.description}</p>
                  {matchingPacks.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Packs using this preset:
                      </p>
                      {matchingPacks.map((pack: any) => {
                        const DomainIcon = DOMAIN_ICONS[pack.domain] || Shield;
                        return (
                          <div key={pack.id} className="flex items-center gap-2 text-xs p-2 rounded bg-accent/20">
                            <DomainIcon className="h-3.5 w-3.5 shrink-0" />
                            <span className="font-medium">{pack.name}</span>
                            <span className="text-muted-foreground">
                              - {pack.rules?.length || 0} rules, {pack.alerts?.length || 0} alerts
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

export default function PolicyPacksPage() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Policy Packs</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Out-of-box policy and control templates by security domain with versioned changelogs, prewired dashboards, and
          strictness presets.
        </p>
      </div>

      <div className="flex gap-1 border-b border-border/50 overflow-x-auto">
        {TABS.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-cyan-400 text-cyan-400"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              <TabIcon className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "overview" && <OverviewTab />}
      {activeTab === "catalog" && <CatalogTab />}
      {activeTab === "activations" && <ActivationsTab />}
      {activeTab === "changelog" && <ChangelogTab />}
      {activeTab === "presets" && <PresetsTab />}
      {/* 82.3 — Acknowledgment Tracking */}
      {activeTab === "acknowledgments" && (
        <Card className="glass-subtle">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <FileCheck2 className="h-5 w-5" /> Policy Acknowledgment Tracking
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-lg border border-border/50 bg-card/50 p-4 text-center">
                  <Users className="h-5 w-5 mx-auto mb-1 text-emerald-400" />
                  <p className="text-xl font-bold">0</p>
                  <p className="text-xs text-muted-foreground">Acknowledged</p>
                </div>
                <div className="rounded-lg border border-border/50 bg-card/50 p-4 text-center">
                  <Clock className="h-5 w-5 mx-auto mb-1 text-amber-400" />
                  <p className="text-xl font-bold">0</p>
                  <p className="text-xs text-muted-foreground">Pending</p>
                </div>
                <div className="rounded-lg border border-border/50 bg-card/50 p-4 text-center">
                  <AlertTriangle className="h-5 w-5 mx-auto mb-1 text-red-400" />
                  <p className="text-xl font-bold">0</p>
                  <p className="text-xs text-muted-foreground">Overdue</p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground text-center py-6">
                <Eye className="h-8 w-8 mx-auto mb-2 opacity-30" />
                Acknowledgment tracking becomes active when policies are distributed to team members.
              </p>
            </div>
          </CardContent>
        </Card>
      )}
      {/* 82.6 — Distribution */}
      {activeTab === "distribution" && (
        <Card className="glass-subtle">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Send className="h-5 w-5" /> Policy Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Distribute activated policy packs to team members via email, Slack, or in-app notifications. Track
                acknowledgment status and send reminders for overdue policies.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="rounded-lg border border-border/50 bg-card/50 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Send className="h-4 w-4 text-cyan-400" />
                    <span className="text-sm font-medium">Email</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Send policy documents directly to team member inboxes</p>
                </div>
                <div className="rounded-lg border border-border/50 bg-card/50 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="h-4 w-4 text-violet-400" />
                    <span className="text-sm font-medium">Slack</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Post policy updates to designated Slack channels</p>
                </div>
                <div className="rounded-lg border border-border/50 bg-card/50 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    <span className="text-sm font-medium">In-App</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Show policy notifications within the platform</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
