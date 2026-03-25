import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  KeyRound,
  RefreshCw,
  AlertTriangle,
  Clock,
  CheckCircle2,
  Loader2,
  Filter,
  Calendar,
  Shield,
  ChevronRight,
  Database,
  Globe,
  Fingerprint,
  Key,
  Server,
  Lock,
  ShieldCheck,
  FileKey,
  BarChart3,
  Activity,
  AlertCircle,
  Play,
  GitBranch,
  Search,
  XCircle,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { Link } from "wouter";

interface SecretRotation {
  id: string;
  connectorId: string;
  orgId: string | null;
  secretField: string;
  lastRotatedAt: string | null;
  nextRotationDue: string | null;
  rotationIntervalDays: number | null;
  status: string;
  rotatedBy: string | null;
  rotatedByName: string | null;
  reminderSentAt: string | null;
  createdAt: string | null;
}

// ─── 29.1 Secret Inventory Types ────────────────────────────────────────────

interface InventorySecret {
  id: string;
  connectorId: string;
  secretField: string;
  secretCategory: string;
  ageInDays: number | null;
  lastRotatedAt: string | null;
  nextRotationDue: string | null;
  daysUntilDue: number | null;
  rotationIntervalDays: number;
  healthStatus: string;
  rotatedBy: string | null;
  status: string;
}

interface InventoryResponse {
  secrets: InventorySecret[];
  total: number;
  summary: {
    byCategory: Record<string, number>;
    byHealth: Record<string, number>;
    expired: number;
    critical: number;
    warning: number;
    healthy: number;
  };
}

// ─── 29.3 Certificate Timeline Types ────────────────────────────────────────

interface CertTimelineEntry {
  id: string;
  connectorId: string;
  secretField: string;
  expiresAt: string | null;
  daysUntilExpiry: number | null;
  alertLevel: string;
  lastRotatedAt: string | null;
  autoRenewable: boolean;
  rotatedBy: string | null;
}

interface CertTimelineResponse {
  certificates: CertTimelineEntry[];
  total: number;
  expiredCount: number;
  expiringWithin7d: number;
  expiringWithin30d: number;
}

// ─── 29.5 Impact Analysis Types ─────────────────────────────────────────────

interface ImpactAnalysis {
  rotationId: string;
  secretField: string;
  connectorId: string;
  connectorName: string;
  dependentServices: Array<{
    name: string;
    type: string;
    criticality: string;
    potentialDowntime: string;
  }>;
  totalDependents: number;
  isSharedCredential: boolean;
  riskLevel: string;
  recommendations: string[];
  estimatedDowntime: string;
  rollbackAvailable: boolean;
}

type StatusFilter = "all" | "overdue" | "due_soon" | "ok";

const CATEGORY_ICONS: Record<string, typeof Key> = {
  api_key: Key,
  certificate: ShieldCheck,
  database_password: Database,
  ssh_key: Fingerprint,
  oauth_token: Globe,
  service_account: Server,
  other: FileKey,
};

const CATEGORY_LABELS: Record<string, string> = {
  api_key: "API Keys",
  certificate: "Certificates",
  database_password: "Database Passwords",
  ssh_key: "SSH Keys",
  oauth_token: "OAuth Tokens",
  service_account: "Service Accounts",
  other: "Other",
};

// ─── 29.2 Health Status Config ──────────────────────────────────────────────

const HEALTH_CONFIG: Record<
  string,
  { color: string; bgColor: string; borderColor: string; label: string; dot: string }
> = {
  healthy: {
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/30",
    label: "Healthy",
    dot: "bg-emerald-400",
  },
  approaching: {
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/30",
    label: "Approaching",
    dot: "bg-yellow-400",
  },
  warning: {
    color: "text-orange-400",
    bgColor: "bg-orange-500/10",
    borderColor: "border-orange-500/30",
    label: "Warning",
    dot: "bg-orange-400",
  },
  critical: {
    color: "text-red-400",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/30",
    label: "Critical",
    dot: "bg-red-400",
  },
  expired: {
    color: "text-red-400",
    bgColor: "bg-red-500/15",
    borderColor: "border-red-500/40",
    label: "Expired",
    dot: "bg-red-500",
  },
};

function getDaysUntilDue(nextDue: string | null): number | null {
  if (!nextDue) return null;
  const now = new Date();
  const due = new Date(nextDue);
  return Math.ceil((due.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

function getUrgencyInfo(daysUntil: number | null): {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
  category: "overdue" | "due_soon" | "ok";
} {
  if (daysUntil === null) {
    return {
      label: "Unknown",
      color: "text-muted-foreground",
      bgColor: "bg-muted/50",
      borderColor: "border-muted",
      category: "ok",
    };
  }
  if (daysUntil < 0) {
    return {
      label: "Overdue",
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/30",
      category: "overdue",
    };
  }
  if (daysUntil <= 7) {
    return {
      label: "Critical",
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
      borderColor: "border-orange-500/30",
      category: "due_soon",
    };
  }
  if (daysUntil <= 14) {
    return {
      label: "Warning",
      color: "text-yellow-400",
      bgColor: "bg-yellow-500/10",
      borderColor: "border-yellow-500/30",
      category: "due_soon",
    };
  }
  return {
    label: "OK",
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/30",
    category: "ok",
  };
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "\u2014";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function formatRelative(dateStr: string | null): string {
  if (!dateStr) return "\u2014";
  const days = getDaysUntilDue(dateStr);
  if (days === null) return "\u2014";
  if (days < 0) return `${Math.abs(days)}d overdue`;
  if (days === 0) return "Today";
  if (days === 1) return "Tomorrow";
  return `${days}d`;
}

// ─── 29.1 Secret Inventory Dashboard Tab ────────────────────────────────────

function SecretInventoryTab() {
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [healthFilter, setHealthFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const { data, isLoading, isError, refetch } = useQuery<InventoryResponse>({
    queryKey: ["/api/secret-rotations/inventory"],
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={`inv-sk-${i}`} className="h-24" />
        ))}
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">Failed to load secret inventory</p>
        <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
          Retry
        </Button>
      </div>
    );
  }

  const filtered = data.secrets.filter((s) => {
    if (categoryFilter !== "all" && s.secretCategory !== categoryFilter) return false;
    if (healthFilter !== "all" && s.healthStatus !== healthFilter) return false;
    if (
      searchQuery &&
      !s.secretField.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !s.secretCategory.toLowerCase().includes(searchQuery.toLowerCase())
    )
      return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Category summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
        {Object.entries(data.summary.byCategory).map(([cat, count]) => {
          const CatIcon = CATEGORY_ICONS[cat] || FileKey;
          return (
            <Card
              key={cat}
              className={`cursor-pointer transition-all hover:border-primary/40 ${
                categoryFilter === cat ? "border-primary/50 bg-primary/5" : ""
              }`}
              onClick={() => setCategoryFilter(categoryFilter === cat ? "all" : cat)}
            >
              <CardContent className="p-3 text-center">
                <CatIcon className="h-4 w-4 mx-auto mb-1 text-muted-foreground" />
                <p className="text-lg font-bold tabular-nums">{count}</p>
                <p className="text-[10px] text-muted-foreground">{CATEGORY_LABELS[cat] || cat}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Health summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {(["expired", "critical", "warning", "healthy"] as const).map((health) => {
          const cfg = HEALTH_CONFIG[health] || HEALTH_CONFIG.healthy;
          const count = data.summary[health] || 0;
          return (
            <Card
              key={health}
              className={`cursor-pointer transition-all hover:${cfg.borderColor} ${
                healthFilter === health ? `${cfg.borderColor} ${cfg.bgColor}` : ""
              }`}
              onClick={() => setHealthFilter(healthFilter === health ? "all" : health)}
            >
              <CardContent className="p-3 flex items-center gap-3">
                <div className={`w-2.5 h-2.5 rounded-full ${cfg.dot}`} />
                <div>
                  <p className={`text-xl font-bold tabular-nums ${cfg.color}`}>{count}</p>
                  <p className="text-[10px] text-muted-foreground">{cfg.label}</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Search + filters */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search secrets..."
            className="pl-8 h-8 text-xs"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        {(categoryFilter !== "all" || healthFilter !== "all") && (
          <Button
            size="sm"
            variant="ghost"
            className="h-8 text-xs"
            onClick={() => {
              setCategoryFilter("all");
              setHealthFilter("all");
            }}
          >
            Clear filters
          </Button>
        )}
      </div>

      {/* Inventory table */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Database className="h-4 w-4 text-muted-foreground" />
            Secret Inventory ({filtered.length} of {data.total})
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="p-8 text-center">
              <SuccessIcon size={32} color="#22c55e" />
              <p className="text-sm text-muted-foreground">No secrets match filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Health</TableHead>
                    <TableHead className="text-xs">Type</TableHead>
                    <TableHead className="text-xs">Secret Field</TableHead>
                    <TableHead className="text-xs">Age (days)</TableHead>
                    <TableHead className="text-xs">Last Rotated</TableHead>
                    <TableHead className="text-xs">Next Due</TableHead>
                    <TableHead className="text-xs text-right">Days Left</TableHead>
                    <TableHead className="text-xs">Interval</TableHead>
                    <TableHead className="text-xs">Rotated By</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((secret) => {
                    const healthCfg = HEALTH_CONFIG[secret.healthStatus] || HEALTH_CONFIG.healthy;
                    const CatIcon = CATEGORY_ICONS[secret.secretCategory] || FileKey;

                    return (
                      <TableRow key={secret.id}>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${healthCfg.color} ${healthCfg.bgColor} ${healthCfg.borderColor}`}
                          >
                            <div className={`w-1.5 h-1.5 rounded-full mr-1 ${healthCfg.dot}`} />
                            {healthCfg.label}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <CatIcon className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="text-xs">
                              {CATEGORY_LABELS[secret.secretCategory] || secret.secretCategory}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{secret.secretField}</TableCell>
                        <TableCell className="text-xs tabular-nums text-muted-foreground">
                          {secret.ageInDays !== null ? `${secret.ageInDays}d` : "\u2014"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatDate(secret.lastRotatedAt)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatDate(secret.nextRotationDue)}
                        </TableCell>
                        <TableCell className="text-right">
                          <span className={`text-xs font-mono tabular-nums font-medium ${healthCfg.color}`}>
                            {secret.daysUntilDue !== null
                              ? secret.daysUntilDue < 0
                                ? `${Math.abs(secret.daysUntilDue)}d overdue`
                                : `${secret.daysUntilDue}d`
                              : "\u2014"}
                          </span>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{secret.rotationIntervalDays}d</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{secret.rotatedBy || "\u2014"}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 29.3 Certificate Expiration Timeline Tab ───────────────────────────────

function CertTimelineTab() {
  const { data, isLoading, isError, refetch } = useQuery<CertTimelineResponse>({
    queryKey: ["/api/secret-rotations/cert-timeline"],
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={`cert-sk-${i}`} className="h-16" />
        ))}
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">Failed to load certificate timeline</p>
        <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
          Retry
        </Button>
      </div>
    );
  }

  const ALERT_COLORS: Record<string, { color: string; bgColor: string; label: string }> = {
    expired: { color: "text-red-400", bgColor: "bg-red-500/10", label: "Expired" },
    "1day": {
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      label: "1 day left",
    },
    "7day": {
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
      label: "< 7 days",
    },
    "14day": {
      color: "text-yellow-400",
      bgColor: "bg-yellow-500/10",
      label: "< 14 days",
    },
    "30day": {
      color: "text-blue-400",
      bgColor: "bg-blue-500/10",
      label: "< 30 days",
    },
    none: {
      color: "text-emerald-400",
      bgColor: "bg-emerald-500/10",
      label: "> 30 days",
    },
  };

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        <Card className="border-border/30">
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10">
              <XCircle className="h-4 w-4 text-red-400" />
            </div>
            <div>
              <p className="text-xl font-bold text-red-400">{data.expiredCount}</p>
              <p className="text-[10px] text-muted-foreground">Expired</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/30">
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10">
              <AlertCircle className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-xl font-bold text-orange-400">{data.expiringWithin7d}</p>
              <p className="text-[10px] text-muted-foreground">Within 7 days</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/30">
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10">
              <Clock className="h-4 w-4 text-blue-400" />
            </div>
            <div>
              <p className="text-xl font-bold text-blue-400">{data.expiringWithin30d}</p>
              <p className="text-[10px] text-muted-foreground">Within 30 days</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Calendar className="h-4 w-4 text-muted-foreground" />
            Certificate Expiration Timeline
          </CardTitle>
          <CardDescription className="text-xs">
            {data.total} certificate{data.total !== 1 ? "s" : ""} tracked
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0">
          {data.certificates.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <ShieldCheck className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No certificates tracked</p>
            </div>
          ) : (
            <div className="space-y-2">
              {data.certificates.map((cert) => {
                const alertCfg = ALERT_COLORS[cert.alertLevel] || ALERT_COLORS.none;
                return (
                  <div
                    key={cert.id}
                    className={`flex items-center justify-between p-3 rounded-lg border ${
                      cert.alertLevel === "expired" || cert.alertLevel === "1day"
                        ? "border-red-500/30 bg-red-500/5"
                        : cert.alertLevel === "7day"
                          ? "border-orange-500/20 bg-orange-500/5"
                          : "border-border/30"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-1.5 rounded-md ${alertCfg.bgColor}`}>
                        <ShieldCheck className={`h-3.5 w-3.5 ${alertCfg.color}`} />
                      </div>
                      <div>
                        <p className="text-sm font-mono">{cert.secretField}</p>
                        <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                          <span>Connector: {cert.connectorId.slice(0, 8)}...</span>
                          {cert.lastRotatedAt && <span>Last rotated: {formatDate(cert.lastRotatedAt)}</span>}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {cert.autoRenewable && (
                        <Badge
                          variant="outline"
                          className="text-[10px] bg-green-500/10 text-green-400 border-green-500/30"
                        >
                          Auto-Renewable
                        </Badge>
                      )}
                      <div className="text-right">
                        <Badge variant="outline" className={`text-[10px] ${alertCfg.color} ${alertCfg.bgColor}`}>
                          {alertCfg.label}
                        </Badge>
                        <p className="text-[10px] text-muted-foreground mt-0.5">
                          {cert.expiresAt ? formatDate(cert.expiresAt) : "No date"}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 29.4 + 29.5 Rotation Actions Tab ──────────────────────────────────────

function RotationActionsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedRotation, setSelectedRotation] = useState<string | null>(null);

  const { data: inventory, isLoading } = useQuery<InventoryResponse>({
    queryKey: ["/api/secret-rotations/inventory"],
  });

  const { data: impact } = useQuery<ImpactAnalysis>({
    queryKey: ["/api/secret-rotations", selectedRotation, "impact"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/secret-rotations/${selectedRotation}/impact`);
      return res.json();
    },
    enabled: !!selectedRotation,
  });

  const rotateMutation = useMutation({
    mutationFn: async (rotationId: string) => {
      const res = await apiRequest("POST", `/api/secret-rotations/${rotationId}/auto-rotate`);
      return res.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Rotation initiated",
        description: `${data.secretField} rotated. Next due: ${formatDate(data.nextDue)}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/secret-rotations/inventory"] });
      setSelectedRotation(null);
    },
    onError: () => {
      toast({ title: "Rotation failed", variant: "destructive" });
    },
  });

  const secrets = inventory?.secrets || [];
  const actionableSecrets = secrets.filter(
    (s) => s.healthStatus === "expired" || s.healthStatus === "critical" || s.healthStatus === "warning",
  );

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={`ra-sk-${i}`} className="h-20" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Play className="h-4 w-4 text-primary" />
            Rotation Actions
          </CardTitle>
          <CardDescription className="text-xs">
            {actionableSecrets.length} secret{actionableSecrets.length !== 1 ? "s" : ""} need attention
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 space-y-2">
          {actionableSecrets.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <SuccessIcon size={32} color="#22c55e" />
              <p className="text-sm">All secrets are healthy</p>
              <p className="text-xs mt-1">No rotations needed at this time</p>
            </div>
          ) : (
            actionableSecrets.map((secret) => {
              const healthCfg = HEALTH_CONFIG[secret.healthStatus] || HEALTH_CONFIG.healthy;
              const isSelected = selectedRotation === secret.id;

              return (
                <Card key={secret.id} className={`border-border/30 ${isSelected ? "ring-1 ring-primary" : ""}`}>
                  <CardContent className="p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <div className={`w-2 h-2 rounded-full ${healthCfg.dot}`} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-mono truncate">{secret.secretField}</span>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${healthCfg.color} ${healthCfg.bgColor} ${healthCfg.borderColor}`}
                            >
                              {healthCfg.label}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                            <span>{CATEGORY_LABELS[secret.secretCategory] || secret.secretCategory}</span>
                            <span>
                              {secret.daysUntilDue !== null
                                ? secret.daysUntilDue < 0
                                  ? `${Math.abs(secret.daysUntilDue)}d overdue`
                                  : `${secret.daysUntilDue}d left`
                                : "No date"}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => setSelectedRotation(isSelected ? null : secret.id)}
                        >
                          <GitBranch className="h-3 w-3 mr-1" />
                          Impact
                        </Button>
                        <Button
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => rotateMutation.mutate(secret.id)}
                          disabled={rotateMutation.isPending}
                        >
                          {rotateMutation.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin mr-1" />
                          ) : (
                            <RefreshCw className="h-3 w-3 mr-1" />
                          )}
                          Rotate
                        </Button>
                      </div>
                    </div>

                    {/* 29.5 Impact Analysis */}
                    {isSelected && impact && (
                      <div className="mt-3 pt-3 border-t border-border/30 space-y-3">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-medium">Impact Analysis</span>
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${
                              impact.riskLevel === "high"
                                ? "text-red-400 bg-red-500/10 border-red-500/30"
                                : impact.riskLevel === "medium"
                                  ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                                  : "text-green-400 bg-green-500/10 border-green-500/30"
                            }`}
                          >
                            {impact.riskLevel} risk
                          </Badge>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                          <div>
                            <span className="text-muted-foreground">Dependents</span>
                            <p className="font-medium">{impact.totalDependents}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Downtime</span>
                            <p className="font-medium">{impact.estimatedDowntime}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Shared</span>
                            <p className="font-medium">{impact.isSharedCredential ? "Yes" : "No"}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Rollback</span>
                            <p className="font-medium">{impact.rollbackAvailable ? "Available" : "N/A"}</p>
                          </div>
                        </div>

                        {impact.dependentServices.length > 0 && (
                          <div className="space-y-1">
                            <span className="text-xs text-muted-foreground">Dependent Services:</span>
                            {impact.dependentServices.map((svc, idx) => (
                              <div
                                key={idx}
                                className="flex items-center justify-between p-2 rounded-md bg-muted/10 text-xs"
                              >
                                <div className="flex items-center gap-2">
                                  <Server className="h-3 w-3 text-muted-foreground" />
                                  <span>{svc.name}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <Badge
                                    variant="outline"
                                    className={`text-[10px] ${
                                      svc.criticality === "high"
                                        ? "text-red-400 bg-red-500/10"
                                        : "text-yellow-400 bg-yellow-500/10"
                                    }`}
                                  >
                                    {svc.criticality}
                                  </Badge>
                                  <span className="text-muted-foreground">{svc.potentialDowntime}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}

                        <div className="space-y-1">
                          <span className="text-xs text-muted-foreground">Recommendations:</span>
                          <ul className="text-xs space-y-0.5 list-disc list-inside text-muted-foreground">
                            {impact.recommendations.map((rec, idx) => (
                              <li key={idx}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page Component ────────────────────────────────────────────────────

export default function SecretRotationOverviewPage() {
  usePageTitle("Secret Rotation Overview");
  const [activeTab, setActiveTab] = useState("schedule");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [daysAhead, setDaysAhead] = useState(90);

  const {
    data: rotations,
    isPending,
    isError,
    refetch,
    isFetching,
  } = useQuery<SecretRotation[]>({
    queryKey: ["/api/secret-rotations/expiring", daysAhead],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/secret-rotations/expiring?days=${daysAhead}`);
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
  });

  const filtered = (rotations ?? []).filter((r) => {
    if (statusFilter === "all") return true;
    const days = getDaysUntilDue(r.nextRotationDue);
    const info = getUrgencyInfo(days);
    return info.category === statusFilter;
  });

  const overdueCount = (rotations ?? []).filter((r) => {
    const d = getDaysUntilDue(r.nextRotationDue);
    return d !== null && d < 0;
  }).length;

  const dueSoonCount = (rotations ?? []).filter((r) => {
    const d = getDaysUntilDue(r.nextRotationDue);
    return d !== null && d >= 0 && d <= 14;
  }).length;

  const okCount = (rotations ?? []).filter((r) => {
    const d = getDaysUntilDue(r.nextRotationDue);
    return d !== null && d > 14;
  }).length;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
            <KeyRound className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Secret Rotation Management</h1>
            <p className="text-xs text-muted-foreground">
              Inventory, health monitoring, certificate tracking, and automated rotation
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Select value={String(daysAhead)} onValueChange={(v) => setDaysAhead(Number(v))}>
            <SelectTrigger className="w-[130px] h-8 text-xs">
              <Calendar className="h-3.5 w-3.5 mr-1.5" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Next 7 days</SelectItem>
              <SelectItem value="14">Next 14 days</SelectItem>
              <SelectItem value="30">Next 30 days</SelectItem>
              <SelectItem value="60">Next 60 days</SelectItem>
              <SelectItem value="90">Next 90 days</SelectItem>
              <SelectItem value="180">Next 180 days</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching} className="h-8">
            {isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            <span className="ml-1.5 hidden sm:inline">Refresh</span>
          </Button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Card
          className={`cursor-pointer transition-all hover:border-red-500/40 ${statusFilter === "overdue" ? "border-red-500/50 bg-red-500/5" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "overdue" ? "all" : "overdue")}
        >
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-red-400">
                {isPending ? <Skeleton className="h-7 w-8 inline-block" /> : overdueCount}
              </p>
              <p className="text-[11px] text-muted-foreground">Overdue</p>
            </div>
          </CardContent>
        </Card>
        <Card
          className={`cursor-pointer transition-all hover:border-orange-500/40 ${statusFilter === "due_soon" ? "border-orange-500/50 bg-orange-500/5" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "due_soon" ? "all" : "due_soon")}
        >
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <Clock className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-orange-400">
                {isPending ? <Skeleton className="h-7 w-8 inline-block" /> : dueSoonCount}
              </p>
              <p className="text-[11px] text-muted-foreground">Due Soon (14d)</p>
            </div>
          </CardContent>
        </Card>
        <Card
          className={`cursor-pointer transition-all hover:border-emerald-500/40 ${statusFilter === "ok" ? "border-emerald-500/50 bg-emerald-500/5" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "ok" ? "all" : "ok")}
        >
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <SuccessIcon size={16} color="#22c55e" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-emerald-400">
                {isPending ? <Skeleton className="h-7 w-8 inline-block" /> : okCount}
              </p>
              <p className="text-[11px] text-muted-foreground">Healthy</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30 border border-border/30 h-auto gap-0.5 p-1">
          <TabsTrigger value="schedule" className="text-xs data-[state=active]:bg-primary/20">
            <Shield className="h-3 w-3 mr-1" />
            Schedule
          </TabsTrigger>
          <TabsTrigger value="inventory" className="text-xs data-[state=active]:bg-primary/20">
            <Database className="h-3 w-3 mr-1" />
            Inventory
          </TabsTrigger>
          <TabsTrigger value="certificates" className="text-xs data-[state=active]:bg-primary/20">
            <ShieldCheck className="h-3 w-3 mr-1" />
            Certificates
          </TabsTrigger>
          <TabsTrigger value="actions" className="text-xs data-[state=active]:bg-primary/20">
            <Play className="h-3 w-3 mr-1" />
            Rotation Actions
          </TabsTrigger>
        </TabsList>

        {/* Schedule tab (existing) */}
        <TabsContent value="schedule" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    Rotation Schedule
                  </CardTitle>
                  <CardDescription className="text-xs mt-1">
                    {filtered.length} rotation{filtered.length !== 1 ? "s" : ""} showing
                    {statusFilter !== "all" && ` (filtered: ${statusFilter.replace("_", " ")})`}
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                  <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
                    <SelectTrigger className="w-[120px] h-7 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="overdue">Overdue</SelectItem>
                      <SelectItem value="due_soon">Due Soon</SelectItem>
                      <SelectItem value="ok">Healthy</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {isPending ? (
                <div className="p-4 space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full" />
                  ))}
                </div>
              ) : isError ? (
                <div className="p-8 text-center">
                  <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">Failed to load rotation data</p>
                  <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
                    Retry
                  </Button>
                </div>
              ) : filtered.length === 0 ? (
                <div className="p-8 text-center">
                  <SuccessIcon size={32} color="#22c55e" />
                  <p className="text-sm font-medium">No rotations found</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {statusFilter !== "all"
                      ? "No rotations match this filter. Try changing the filter."
                      : "No connector secret rotations are scheduled in this time window."}
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-xs">Status</TableHead>
                        <TableHead className="text-xs">Secret Field</TableHead>
                        <TableHead className="text-xs">Connector</TableHead>
                        <TableHead className="text-xs">Last Rotated</TableHead>
                        <TableHead className="text-xs">Next Due</TableHead>
                        <TableHead className="text-xs text-right">Days Left</TableHead>
                        <TableHead className="text-xs">Interval</TableHead>
                        <TableHead className="text-xs">Rotated By</TableHead>
                        <TableHead className="text-xs w-8" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filtered.map((rotation) => {
                        const daysUntil = getDaysUntilDue(rotation.nextRotationDue);
                        const urgency = getUrgencyInfo(daysUntil);
                        return (
                          <TableRow key={rotation.id} className="group">
                            <TableCell>
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Badge
                                      variant="outline"
                                      className={`text-[10px] ${urgency.color} ${urgency.bgColor} ${urgency.borderColor}`}
                                    >
                                      {urgency.label}
                                    </Badge>
                                  </TooltipTrigger>
                                  <TooltipContent className="text-xs">
                                    {daysUntil !== null
                                      ? daysUntil < 0
                                        ? `Overdue by ${Math.abs(daysUntil)} days`
                                        : `Due in ${daysUntil} days`
                                      : "No due date set"}
                                  </TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                            </TableCell>
                            <TableCell className="font-mono text-xs">{rotation.secretField}</TableCell>
                            <TableCell>
                              <Link href={`/connectors`} className="text-xs text-cyan-400 hover:underline">
                                {rotation.connectorId.slice(0, 8)}...
                              </Link>
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {formatDate(rotation.lastRotatedAt)}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {formatDate(rotation.nextRotationDue)}
                            </TableCell>
                            <TableCell className="text-right">
                              <span className={`text-xs font-mono tabular-nums font-medium ${urgency.color}`}>
                                {formatRelative(rotation.nextRotationDue)}
                              </span>
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {rotation.rotationIntervalDays != null ? `${rotation.rotationIntervalDays}d` : "\u2014"}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {rotation.rotatedByName || "\u2014"}
                            </TableCell>
                            <TableCell>
                              <Link href="/connectors">
                                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                              </Link>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 29.1 Inventory Tab */}
        <TabsContent value="inventory" className="mt-4">
          <SecretInventoryTab />
        </TabsContent>

        {/* 29.3 Certificates Tab */}
        <TabsContent value="certificates" className="mt-4">
          <CertTimelineTab />
        </TabsContent>

        {/* 29.4 + 29.5 Rotation Actions Tab */}
        <TabsContent value="actions" className="mt-4">
          <RotationActionsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
