import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Key,
  Lock,
  Unlock,
  Timer,
  Send,
  UserCheck,
  UserX,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  Zap,
  Eye,
  EyeOff,
  Mail,
  ArrowRightLeft,
  TriangleAlert,
  ClipboardList,
  CheckCircle2,
  XCircle,
  Database,
  Globe,
  Server,
  Fingerprint,
  FileKey,
  Plus,
  AlertCircle,
  BarChart3,
  Video,
  GitBranch,
  Clock,
  TrendingUp,
  Users,
  Activity,
} from "lucide-react";
import { SuccessIcon, EyeToggleIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface JitStats {
  totalSecrets: number;
  criticalSecrets: number;
  secretsNeedingRotation: number;
  pendingRequests: number;
  activeAccesses: number;
  activeShares: number;
  breakGlassActive: number;
  pendingReviews: number;
  transfersThisMonth: number;
  accessRequestsToday: number;
  deniedToday: number;
  avgApprovalTimeMinutes: number;
}

const CLASSIFICATION_CONFIG: Record<string, { color: string; label: string }> = {
  critical: {
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    label: "Critical",
  },
  high: {
    color: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    label: "High",
  },
  medium: {
    color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    label: "Medium",
  },
  low: {
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    label: "Low",
  },
};

const SECRET_TYPE_ICONS: Record<string, typeof Key> = {
  api_key: Key,
  database_credential: Database,
  ssh_key: Fingerprint,
  tls_cert: ShieldCheck,
  oauth_token: Globe,
  encryption_key: Lock,
  service_account: Server,
  other: FileKey,
};

const REQUEST_STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  pending: {
    color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    label: "Pending",
  },
  approved: {
    color: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    label: "Approved",
  },
  denied: {
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    label: "Denied",
  },
  active: {
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    label: "Active",
  },
  released: {
    color: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    label: "Released",
  },
  expired: {
    color: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    label: "Expired",
  },
  revoked: {
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    label: "Revoked",
  },
};

const SHARE_STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  active: {
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    label: "Active",
  },
  consumed: {
    color: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    label: "Consumed",
  },
  expired: {
    color: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    label: "Expired",
  },
  revoked: {
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    label: "Revoked",
  },
};

const BREAK_GLASS_STATUS: Record<string, { color: string; label: string }> = {
  active: {
    color: "bg-red-500/20 text-red-400 border-red-500/30",
    label: "Active",
  },
  expired: {
    color: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    label: "Expired",
  },
  reviewed: {
    color: "bg-green-500/20 text-green-400 border-green-500/30",
    label: "Reviewed",
  },
  revoked: {
    color: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    label: "Revoked",
  },
};

interface StatCardProps {
  title: string;
  value: string | number;
  icon: typeof Key;
  color: string;
  subtitle?: string;
}

function StatCard({ title, value, icon: Icon, color, subtitle }: StatCardProps) {
  return (
    <Card className="border-border/30">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{title}</p>
            <p className="text-2xl font-bold">{value}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <div className={`p-2.5 rounded-lg ${color}`}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── 28.1 Access Request Form with Justification ──────────────────────────

interface TargetSystem {
  id: string;
  name: string;
  type: string;
  classification: string;
  environment: string;
  service: string;
  owner: string;
  approvalChain: string[];
  availableRoles: string[];
  maxDurationMinutes: number;
}

function AccessRequestFormTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedSystem, setSelectedSystem] = useState("");
  const [selectedRole, setSelectedRole] = useState("read");
  const [duration, setDuration] = useState("30");
  const [justification, setJustification] = useState("");

  const { data: targetSystems, isLoading: systemsLoading } = useQuery<TargetSystem[]>({
    queryKey: ["/api/jit-secrets/target-systems"],
  });

  const systemList = Array.isArray(targetSystems) ? targetSystems : [];
  const selected = systemList.find((s) => s.id === selectedSystem);

  const submitMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/jit-secrets/access-requests", {
        secretId: selectedSystem,
        requesterId: "current-user",
        requesterName: "Current User",
        reason: justification,
        durationMinutes: parseInt(duration, 10),
        approverRole: selected?.approvalChain[0] || "owner",
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Access request submitted", description: "Awaiting approval" });
      queryClient.invalidateQueries({ queryKey: ["/api/jit-secrets/access-requests"] });
      setSelectedSystem("");
      setJustification("");
      setDuration("30");
    },
    onError: () => {
      toast({ title: "Failed to submit request", variant: "destructive" });
    },
  });

  const canSubmit = selectedSystem && justification.length >= 10 && parseInt(duration, 10) > 0;

  return (
    <div className="space-y-4">
      <Card className="border-border/30">
        <CardHeader className="py-3 px-4">
          <CardTitle className="text-sm flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" />
            New Access Request
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-0 space-y-4">
          {/* Target System */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Target System / Secret</label>
            {systemsLoading ? (
              <Skeleton className="h-9 w-full" />
            ) : (
              <Select value={selectedSystem} onValueChange={setSelectedSystem}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue placeholder="Select a target system..." />
                </SelectTrigger>
                <SelectContent>
                  {systemList.map((sys) => (
                    <SelectItem key={sys.id} value={sys.id}>
                      <span className="flex items-center gap-2">
                        {sys.name}
                        <Badge
                          variant="outline"
                          className={`text-[10px] px-1 ${CLASSIFICATION_CONFIG[sys.classification]?.color || ""}`}
                        >
                          {sys.classification}
                        </Badge>
                        <span className="text-muted-foreground text-[10px]">{sys.environment}</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          {/* System details */}
          {selected && (
            <Card className="border-border/20 bg-muted/10">
              <CardContent className="p-3 space-y-2">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Type</span>
                    <p className="font-medium">{selected.type.replace(/_/g, " ")}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Environment</span>
                    <p className="font-medium">{selected.environment}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Service</span>
                    <p className="font-medium">{selected.service}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Owner</span>
                    <p className="font-medium">{selected.owner}</p>
                  </div>
                </div>
                <div className="pt-1 border-t border-border/20">
                  <span className="text-[10px] text-muted-foreground">Approval chain: </span>
                  <div className="flex items-center gap-1 mt-0.5">
                    {selected.approvalChain.map((role: string, idx: number) => (
                      <span key={role} className="flex items-center gap-1">
                        {idx > 0 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                        <Badge variant="outline" className="text-[10px] px-1.5">
                          {role}
                        </Badge>
                      </span>
                    ))}
                  </div>
                </div>
                <p className="text-[10px] text-muted-foreground">Max duration: {selected.maxDurationMinutes} minutes</p>
              </CardContent>
            </Card>
          )}

          {/* Role & Duration */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Required Role</label>
              <Select value={selectedRole} onValueChange={setSelectedRole}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(selected?.availableRoles || ["read", "write", "admin"]).map((role: string) => (
                    <SelectItem key={role} value={role}>
                      {role}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Duration (minutes)</label>
              <Select value={duration} onValueChange={setDuration}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="15">15 min</SelectItem>
                  <SelectItem value="30">30 min</SelectItem>
                  <SelectItem value="60">1 hour</SelectItem>
                  <SelectItem value="120">2 hours</SelectItem>
                  <SelectItem value="240">4 hours</SelectItem>
                  <SelectItem value="480">8 hours</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Business Justification */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Business Justification (min 10 chars)</label>
            <Textarea
              placeholder="Describe why you need access, what you plan to do, and expected outcome..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className="min-h-[80px] text-sm"
            />
            <p className="text-[10px] text-muted-foreground text-right">{justification.length} / 10 min characters</p>
          </div>

          <Button
            className="w-full"
            disabled={!canSubmit || submitMutation.isPending}
            onClick={() => submitMutation.mutate()}
          >
            {submitMutation.isPending ? (
              <RefreshCw className="h-4 w-4 animate-spin mr-2" />
            ) : (
              <Send className="h-4 w-4 mr-2" />
            )}
            Submit Access Request
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 28.2 Active Session Monitoring ────────────────────────────────────────

interface ActiveSession {
  sessionId: string;
  secretName: string;
  user: string;
  permissions: string;
  approvedBy: string | null;
  startedAt: string;
  expiresAt: string | null;
  timeRemainingMinutes: number;
  durationMinutes: number;
  progressPercent: number;
  isExpiringSoon: boolean;
  reason: string;
}

interface ActiveSessionsResponse {
  sessions: ActiveSession[];
  totalActive: number;
  expiringSoon: number;
}

function ActiveSessionsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<ActiveSessionsResponse>({
    queryKey: ["/api/jit-secrets/active-sessions"],
    refetchInterval: 15000,
  });

  const revokeMutation = useMutation({
    mutationFn: async ({ id, reason }: { id: string; reason: string }) => {
      const res = await apiRequest("POST", `/api/jit-secrets/active-sessions/${id}/revoke`, {
        revokerName: "Current User",
        reason,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Session revoked" });
      queryClient.invalidateQueries({
        queryKey: ["/api/jit-secrets/active-sessions"],
      });
    },
    onError: () => {
      toast({ title: "Failed to revoke session", variant: "destructive" });
    },
  });

  const sessions = data?.sessions || [];

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-3">
        <Card className="border-border/30">
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <Activity className="h-4 w-4 text-green-400" />
            </div>
            <div>
              <p className="text-xl font-bold">{data?.totalActive ?? 0}</p>
              <p className="text-[11px] text-muted-foreground">Active Sessions</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/30">
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10">
              <AlertCircle className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-xl font-bold text-orange-400">{data?.expiringSoon ?? 0}</p>
              <p className="text-[11px] text-muted-foreground">Expiring Soon (&lt;10min)</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Session list */}
      <Card className="border-border/30">
        <CardHeader className="py-3 px-4">
          <CardTitle className="text-sm flex items-center gap-2">
            <Eye className="h-4 w-4 text-primary" />
            Live Session Monitor
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-0">
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={`session-sk-${i}`} className="h-20" />
              ))}
            </div>
          ) : sessions.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <SuccessIcon size={32} color="#22c55e" />
              <p className="text-sm">No active JIT sessions</p>
              <p className="text-xs mt-1">All privileged access windows are closed</p>
            </div>
          ) : (
            <div className="space-y-2">
              {sessions.map((session) => (
                <Card
                  key={session.sessionId}
                  className={`border-border/30 ${session.isExpiringSoon ? "border-l-2 border-l-orange-500" : ""}`}
                >
                  <CardContent className="p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium">{session.user}</span>
                          <ChevronRight className="h-3 w-3 text-muted-foreground" />
                          <span className="text-sm font-medium">{session.secretName}</span>
                          <Badge
                            variant="outline"
                            className="text-[10px] px-1.5 bg-green-500/20 text-green-400 border-green-500/30"
                          >
                            {session.permissions}
                          </Badge>
                          {session.isExpiringSoon && (
                            <Badge
                              variant="outline"
                              className="text-[10px] px-1.5 bg-orange-500/20 text-orange-400 border-orange-500/30 animate-pulse"
                            >
                              Expiring Soon
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-3 mt-1.5 text-xs text-muted-foreground">
                          <span>Approved by: {session.approvedBy || "N/A"}</span>
                          <span>Started: {new Date(session.startedAt).toLocaleTimeString()}</span>
                          <span className="font-medium text-foreground">
                            {session.timeRemainingMinutes}min remaining
                          </span>
                        </div>
                        {/* Progress bar */}
                        <div className="mt-2 flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${
                                session.progressPercent > 80
                                  ? "bg-orange-500"
                                  : session.progressPercent > 60
                                    ? "bg-yellow-500"
                                    : "bg-green-500"
                              }`}
                              style={{
                                width: `${session.progressPercent}%`,
                              }}
                            />
                          </div>
                          <span className="text-[10px] text-muted-foreground tabular-nums">
                            {session.progressPercent}%
                          </span>
                        </div>
                      </div>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              className="shrink-0 text-red-400 border-red-500/30 hover:bg-red-500/10"
                              onClick={() =>
                                revokeMutation.mutate({
                                  id: session.sessionId,
                                  reason: "Emergency revocation by admin",
                                })
                              }
                              disabled={revokeMutation.isPending}
                            >
                              <XCircle className="h-3.5 w-3.5 mr-1" />
                              Revoke
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Emergency session revocation</TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 28.3 Access Request Analytics ─────────────────────────────────────────

interface AccessAnalytics {
  period: string;
  totalRequests: number;
  approved: number;
  denied: number;
  pending: number;
  approvalRate: number;
  avgDurationMinutes: number;
  topRequesters: Array<{ user: string; count: number }>;
  topSystems: Array<{ system: string; count: number }>;
  unusualPatterns: Array<{
    user: string;
    requestCount: number;
    avgForOrg: number;
    anomalyRatio: number;
    flag: string;
  }>;
}

function AccessAnalyticsTab() {
  const { data, isLoading } = useQuery<AccessAnalytics>({
    queryKey: ["/api/jit-secrets/access-analytics"],
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={`analytics-sk-${i}`} className="h-32" />
        ))}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <BarChart3 className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p>No analytics data available</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          title="Total Requests (30d)"
          value={data.totalRequests}
          icon={ClipboardList}
          color="bg-primary/10 text-primary"
        />
        <StatCard
          title="Approval Rate"
          value={`${data.approvalRate}%`}
          icon={CheckCircle2}
          color="bg-green-500/10 text-green-400"
        />
        <StatCard
          title="Avg Duration"
          value={`${data.avgDurationMinutes}m`}
          icon={Clock}
          color="bg-blue-500/10 text-blue-400"
        />
        <StatCard title="Denied" value={data.denied} icon={XCircle} color="bg-red-500/10 text-red-400" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top Requesters */}
        <Card className="border-border/30">
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-sm flex items-center gap-2">
              <Users className="h-4 w-4 text-primary" />
              Top Requesters (30d)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            {data.topRequesters.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">No data</p>
            ) : (
              <div className="space-y-2">
                {data.topRequesters.map((r, idx) => (
                  <div key={r.user} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-muted-foreground w-4">{idx + 1}.</span>
                      <span className="text-sm">{r.user}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden w-24">
                        <div
                          className="h-full bg-primary rounded-full"
                          style={{
                            width: `${Math.min(100, (r.count / Math.max(1, data.topRequesters[0]?.count || 1)) * 100)}%`,
                          }}
                        />
                      </div>
                      <span className="text-xs font-mono tabular-nums">{r.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top Systems */}
        <Card className="border-border/30">
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-sm flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              Most Requested Systems (30d)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            {data.topSystems.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">No data</p>
            ) : (
              <div className="space-y-2">
                {data.topSystems.map((s, idx) => (
                  <div key={s.system} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-muted-foreground w-4">{idx + 1}.</span>
                      <span className="text-sm truncate max-w-[180px]">{s.system}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden w-24">
                        <div
                          className="h-full bg-cyan-500 rounded-full"
                          style={{
                            width: `${Math.min(100, (s.count / Math.max(1, data.topSystems[0]?.count || 1)) * 100)}%`,
                          }}
                        />
                      </div>
                      <span className="text-xs font-mono tabular-nums">{s.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Unusual Patterns */}
      {data.unusualPatterns.length > 0 && (
        <Card className="border-border/30 border-l-2 border-l-orange-500">
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-sm flex items-center gap-2">
              <TriangleAlert className="h-4 w-4 text-orange-400" />
              Unusual Access Patterns
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0 space-y-2">
            {data.unusualPatterns.map((pattern) => (
              <div
                key={pattern.user}
                className="flex items-center justify-between p-2 rounded-md bg-orange-500/5 border border-orange-500/20"
              >
                <div>
                  <span className="text-sm font-medium">{pattern.user}</span>
                  <p className="text-xs text-muted-foreground">
                    {pattern.requestCount} requests vs org avg {pattern.avgForOrg} ({pattern.anomalyRatio}x normal)
                  </p>
                </div>
                <Badge variant="outline" className="text-[10px] bg-orange-500/20 text-orange-400 border-orange-500/30">
                  {pattern.flag.replace("_", " ")}
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Existing Card Components (unchanged) ──────────────────────────────────

interface SecretCardProps {
  secret: {
    id: string;
    name: string;
    description: string;
    secretType: string;
    classification: string;
    ownerName: string;
    environment: string;
    service: string;
    lastRotatedAt: string;
    needsRotation: boolean;
    noPlaintextSharing: boolean;
    accessCount: number;
    activeAccessors: number;
  };
}

function SecretCard({ secret }: SecretCardProps) {
  const [expanded, setExpanded] = useState(false);
  const cls = CLASSIFICATION_CONFIG[secret.classification] || CLASSIFICATION_CONFIG.low;
  const TypeIcon = SECRET_TYPE_ICONS[secret.secretType] || Key;

  return (
    <Card className="border-border/30 hover:border-border/50 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-primary/10 shrink-0">
              <TypeIcon className="h-4 w-4 text-primary" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h4 className="font-medium text-sm truncate">{secret.name}</h4>
                <Badge variant="outline" className={`text-[10px] px-1.5 ${cls.color}`}>
                  {cls.label}
                </Badge>
                {secret.needsRotation && (
                  <Badge variant="outline" className="text-[10px] px-1.5 bg-red-500/20 text-red-400 border-red-500/30">
                    Rotation Needed
                  </Badge>
                )}
                {secret.noPlaintextSharing && (
                  <Badge
                    variant="outline"
                    className="text-[10px] px-1.5 bg-purple-500/20 text-purple-400 border-purple-500/30"
                  >
                    <EyeOff className="h-3 w-3 mr-1" />
                    No Plaintext
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{secret.description}</p>
              <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                <span>Owner: {secret.ownerName}</span>
                <span>Env: {secret.environment}</span>
                <span>Service: {secret.service}</span>
              </div>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)} className="shrink-0">
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
        </div>
        {expanded && (
          <div className="mt-3 pt-3 border-t border-border/30 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <span className="text-muted-foreground">Type</span>
              <p className="font-medium">{secret.secretType.replace(/_/g, " ")}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Last Rotated</span>
              <p className="font-medium">{new Date(secret.lastRotatedAt).toLocaleDateString()}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Total Accesses</span>
              <p className="font-medium">{secret.accessCount}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Active Accessors</span>
              <p className="font-medium">{secret.activeAccessors}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface AccessRequestRowProps {
  request: {
    id: string;
    secretName: string;
    requesterName: string;
    reason: string;
    durationMinutes: number;
    status: string;
    approverRole: string;
    approvedBy: string | null;
    deniedBy: string | null;
    deniedReason: string | null;
    tokenExpiresAt: string | null;
    releasedAt: string | null;
    createdAt: string;
  };
}

function AccessRequestRow({ request }: AccessRequestRowProps) {
  const [expanded, setExpanded] = useState(false);
  const statusCfg = REQUEST_STATUS_CONFIG[request.status] || REQUEST_STATUS_CONFIG.pending;

  return (
    <Card className="border-border/30">
      <CardContent className="p-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <div className="p-1.5 rounded-md bg-primary/10 shrink-0">
              {request.status === "approved" || request.status === "active" ? (
                <Unlock className="h-3.5 w-3.5 text-green-400" />
              ) : request.status === "denied" ? (
                <XCircle className="h-3.5 w-3.5 text-red-400" />
              ) : request.status === "pending" ? (
                <Timer className="h-3.5 w-3.5 text-yellow-400" />
              ) : (
                <Lock className="h-3.5 w-3.5 text-gray-400" />
              )}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium truncate">{request.requesterName}</span>
                <span className="text-xs text-muted-foreground">requested</span>
                <span className="text-sm font-medium truncate">{request.secretName}</span>
              </div>
              <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground">
                <span>{request.durationMinutes}min</span>
                <span>Approver: {request.approverRole}</span>
                <span>{new Date(request.createdAt).toLocaleString()}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Badge variant="outline" className={`text-[10px] px-1.5 ${statusCfg.color}`}>
              {statusCfg.label}
            </Badge>
            <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)}>
              {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            </Button>
          </div>
        </div>
        {expanded && (
          <div className="mt-2 pt-2 border-t border-border/30 space-y-2 text-xs">
            <div>
              <span className="text-muted-foreground">Reason: </span>
              <span>{request.reason}</span>
            </div>
            {request.approvedBy && (
              <div>
                <span className="text-muted-foreground">Approved by: </span>
                <span>{request.approvedBy}</span>
              </div>
            )}
            {request.deniedBy && (
              <div>
                <span className="text-muted-foreground">Denied by: </span>
                <span>
                  {request.deniedBy} — {request.deniedReason}
                </span>
              </div>
            )}
            {request.tokenExpiresAt && (
              <div>
                <span className="text-muted-foreground">Token expires: </span>
                <span>{new Date(request.tokenExpiresAt).toLocaleString()}</span>
              </div>
            )}
            {request.releasedAt && (
              <div>
                <span className="text-muted-foreground">Released at: </span>
                <span>{new Date(request.releasedAt).toLocaleString()}</span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface ShareCardProps {
  share: {
    id: string;
    secretName: string;
    createdBy: string;
    recipientEmail: string;
    expiresAt: string;
    maxUses: number;
    currentUses: number;
    status: string;
    noPlaintext: boolean;
    createdAt: string;
    consumedAt: string | null;
  };
}

function ShareCard({ share }: ShareCardProps) {
  const statusCfg = SHARE_STATUS_CONFIG[share.status] || SHARE_STATUS_CONFIG.active;

  return (
    <Card className="border-border/30">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 shrink-0">
              <Mail className="h-4 w-4 text-blue-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-medium">{share.secretName}</h4>
                <Badge variant="outline" className={`text-[10px] px-1.5 ${statusCfg.color}`}>
                  {statusCfg.label}
                </Badge>
                {share.noPlaintext && (
                  <Badge
                    variant="outline"
                    className="text-[10px] px-1.5 bg-purple-500/20 text-purple-400 border-purple-500/30"
                  >
                    <EyeOff className="h-3 w-3 mr-1" />
                    Wrapped
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                <span>To: {share.recipientEmail}</span>
                <span>By: {share.createdBy}</span>
              </div>
              <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                <span>
                  Uses: {share.currentUses}/{share.maxUses}
                </span>
                <span>Expires: {new Date(share.expiresAt).toLocaleString()}</span>
                {share.consumedAt && <span>Consumed: {new Date(share.consumedAt).toLocaleString()}</span>}
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface TransferCardProps {
  transfer: {
    id: string;
    secretName: string;
    fromOwnerName: string;
    toOwnerName: string;
    action: string;
    reason: string;
    isOffboarding: boolean;
    initiatedBy: string;
    completedAt: string;
  };
}

function TransferCard({ transfer }: TransferCardProps) {
  return (
    <Card className="border-border/30">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div
            className={`p-2 rounded-lg shrink-0 ${transfer.action === "reclaim" ? "bg-red-500/10" : "bg-blue-500/10"}`}
          >
            <ArrowRightLeft className={`h-4 w-4 ${transfer.action === "reclaim" ? "text-red-400" : "text-blue-400"}`} />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-medium">{transfer.secretName}</h4>
              <Badge
                variant="outline"
                className={`text-[10px] px-1.5 ${transfer.action === "reclaim" ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-blue-500/20 text-blue-400 border-blue-500/30"}`}
              >
                {transfer.action === "reclaim" ? "Forced Reclaim" : "Transfer"}
              </Badge>
              {transfer.isOffboarding && (
                <Badge
                  variant="outline"
                  className="text-[10px] px-1.5 bg-orange-500/20 text-orange-400 border-orange-500/30"
                >
                  Offboarding
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1 text-xs">
              <span className="text-muted-foreground">{transfer.fromOwnerName}</span>
              <ArrowRightLeft className="h-3 w-3 text-muted-foreground" />
              <span className="font-medium">{transfer.toOwnerName}</span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">{transfer.reason}</p>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
              <span>By: {transfer.initiatedBy}</span>
              <span>{new Date(transfer.completedAt).toLocaleString()}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface BreakGlassCardProps {
  entry: {
    id: string;
    secretName: string;
    requesterName: string;
    justification: string;
    incidentId: string | null;
    status: string;
    durationMinutes: number;
    retroactiveReviewRequired: boolean;
    reviewedBy: string | null;
    reviewedAt: string | null;
    reviewNotes: string | null;
    createdAt: string;
    expiresAt: string;
  };
}

function BreakGlassCard({ entry }: BreakGlassCardProps) {
  const [expanded, setExpanded] = useState(false);
  const statusCfg = BREAK_GLASS_STATUS[entry.status] || BREAK_GLASS_STATUS.active;

  return (
    <Card className={`border-border/30 ${entry.retroactiveReviewRequired ? "border-l-2 border-l-red-500" : ""}`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1">
            <div className="p-2 rounded-lg bg-red-500/10 shrink-0">
              <Zap className="h-4 w-4 text-red-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h4 className="text-sm font-medium">{entry.secretName}</h4>
                <Badge variant="outline" className={`text-[10px] px-1.5 ${statusCfg.color}`}>
                  {statusCfg.label}
                </Badge>
                {entry.retroactiveReviewRequired && (
                  <Badge
                    variant="outline"
                    className="text-[10px] px-1.5 bg-red-500/20 text-red-400 border-red-500/30 animate-pulse"
                  >
                    Review Required
                  </Badge>
                )}
                {entry.incidentId && (
                  <Badge
                    variant="outline"
                    className="text-[10px] px-1.5 bg-orange-500/20 text-orange-400 border-orange-500/30"
                  >
                    {entry.incidentId}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                <span>By: {entry.requesterName}</span>
                <span>{entry.durationMinutes}min</span>
                <span>{new Date(entry.createdAt).toLocaleString()}</span>
              </div>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)} className="shrink-0">
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
        </div>
        {expanded && (
          <div className="mt-3 pt-3 border-t border-border/30 space-y-2 text-xs">
            <div>
              <span className="text-muted-foreground">Justification: </span>
              <span>{entry.justification}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Expires: </span>
              <span>{new Date(entry.expiresAt).toLocaleString()}</span>
            </div>
            {entry.reviewedBy && (
              <div>
                <span className="text-muted-foreground">Reviewed by: </span>
                <span>
                  {entry.reviewedBy} on {entry.reviewedAt ? new Date(entry.reviewedAt).toLocaleString() : "N/A"}
                </span>
              </div>
            )}
            {entry.reviewNotes && (
              <div>
                <span className="text-muted-foreground">Review notes: </span>
                <span>{entry.reviewNotes}</span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface AuditEntryRowProps {
  entry: {
    action: string;
    actor: string;
    timestamp: string;
    details?: string;
  };
}

function AuditEntryRow({ entry }: AuditEntryRowProps) {
  const actionColors: Record<string, string> = {
    access_approved: "text-green-400",
    access_denied: "text-red-400",
    access_requested: "text-yellow-400",
    access_released: "text-gray-400",
    break_glass_activated: "text-red-400",
    break_glass_reviewed: "text-green-400",
    share_created: "text-blue-400",
    share_consumed: "text-blue-400",
    ownership_reclaimed: "text-orange-400",
    ownership_transferred: "text-blue-400",
    secret_registered: "text-primary",
    rotation_prompted: "text-yellow-400",
    session_revoked: "text-red-400",
  };

  return (
    <div className="flex items-start gap-3 py-2 px-3 rounded-md hover:bg-muted/20 transition-colors">
      <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-mono ${actionColors[entry.action] || "text-muted-foreground"}`}>
            {entry.action}
          </span>
          <span className="text-xs text-muted-foreground">by</span>
          <span className="text-xs font-medium">{entry.actor}</span>
        </div>
        {entry.details && <p className="text-xs text-muted-foreground mt-0.5">{entry.details}</p>}
        <p className="text-[10px] text-muted-foreground mt-0.5">{new Date(entry.timestamp).toLocaleString()}</p>
      </div>
    </div>
  );
}

// ─── Main Page Component ───────────────────────────────────────────────────

export default function JitSecretAccessPage() {
  const [activeTab, setActiveTab] = useState("request");
  const [searchQuery, setSearchQuery] = useState("");

  const { data: secrets, isLoading: secretsLoading } = useQuery<SecretCardProps["secret"][]>({
    queryKey: ["/api/jit-secrets/secrets"],
  });

  const { data: stats, isLoading: statsLoading } = useQuery<JitStats>({
    queryKey: ["/api/jit-secrets/stats"],
  });

  const { data: accessRequests, isLoading: requestsLoading } = useQuery<AccessRequestRowProps["request"][]>({
    queryKey: ["/api/jit-secrets/access-requests"],
  });

  const { data: shares, isLoading: sharesLoading } = useQuery<ShareCardProps["share"][]>({
    queryKey: ["/api/jit-secrets/shares"],
  });

  const { data: transfers, isLoading: transfersLoading } = useQuery<TransferCardProps["transfer"][]>({
    queryKey: ["/api/jit-secrets/transfers"],
  });

  const { data: breakGlass, isLoading: breakGlassLoading } = useQuery<BreakGlassCardProps["entry"][]>({
    queryKey: ["/api/jit-secrets/break-glass"],
  });

  const { data: auditLog, isLoading: auditLoading } = useQuery<AuditEntryRowProps["entry"][]>({
    queryKey: ["/api/jit-secrets/audit-log"],
  });

  const secretList = Array.isArray(secrets) ? secrets : [];
  const requestList = Array.isArray(accessRequests) ? accessRequests : [];
  const shareList = Array.isArray(shares) ? shares : [];
  const transferList = Array.isArray(transfers) ? transfers : [];
  const breakGlassList = Array.isArray(breakGlass) ? breakGlass : [];
  const auditList = Array.isArray(auditLog) ? auditLog : [];

  const filteredSecrets = secretList.filter(
    (s: { name: string; description: string; ownerName: string; environment: string }) =>
      !searchQuery ||
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.ownerName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.environment.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredRequests = requestList.filter(
    (r: { secretName: string; requesterName: string; reason: string }) =>
      !searchQuery ||
      r.secretName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.requesterName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.reason.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const tabs = [
    { id: "request", label: "Request Access", icon: Plus },
    { id: "sessions", label: "Active Sessions", icon: Activity },
    { id: "secrets", label: "Secrets", count: secretList.length },
    { id: "requests", label: "History", count: requestList.length },
    { id: "analytics", label: "Analytics", icon: BarChart3 },
    { id: "shares", label: "Shares", count: shareList.length },
    { id: "ownership", label: "Ownership", count: transferList.length },
    { id: "break-glass", label: "Break-Glass", count: breakGlassList.length },
    { id: "audit", label: "Audit Log", count: auditList.length },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            JIT Secret Access
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Just-in-time privileged access, session monitoring, analytics, and audit
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search secrets, requests..."
              className="pl-9 w-64 h-9 text-sm"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={`stat-skeleton-${i}`} className="h-24" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard title="Total Secrets" value={stats.totalSecrets} icon={Key} color="bg-primary/10 text-primary" />
          <StatCard
            title="Critical"
            value={stats.criticalSecrets}
            icon={ShieldAlert}
            color="bg-red-500/10 text-red-400"
          />
          <StatCard
            title="Needs Rotation"
            value={stats.secretsNeedingRotation}
            icon={RefreshCw}
            color="bg-yellow-500/10 text-yellow-400"
          />
          <StatCard
            title="Pending Requests"
            value={stats.pendingRequests}
            icon={Timer}
            color="bg-orange-500/10 text-orange-400"
          />
          <StatCard
            title="Active Accesses"
            value={stats.activeAccesses}
            icon={Unlock}
            color="bg-green-500/10 text-green-400"
          />
          <StatCard
            title="Break-Glass"
            value={stats.breakGlassActive}
            icon={Zap}
            color="bg-red-500/10 text-red-400"
            subtitle={stats.pendingReviews > 0 ? `${stats.pendingReviews} review pending` : undefined}
          />
        </div>
      ) : (
        <div className="text-center py-8 text-muted-foreground">No stats available</div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30 border border-border/30 flex-wrap h-auto gap-0.5 p-1">
          {tabs.map((tab) => (
            <TabsTrigger key={tab.id} value={tab.id} className="text-xs data-[state=active]:bg-primary/20">
              {"icon" in tab && tab.icon ? (
                <>
                  <tab.icon className="h-3 w-3 mr-1" />
                  {tab.label}
                </>
              ) : (
                <>
                  {tab.label}
                  {"count" in tab && (
                    <Badge variant="secondary" className="ml-1.5 text-[10px] px-1 py-0 h-4 min-w-[18px]">
                      {tab.count}
                    </Badge>
                  )}
                </>
              )}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* 28.1 Access Request Form */}
        <TabsContent value="request" className="mt-4">
          <AccessRequestFormTab />
        </TabsContent>

        {/* 28.2 Active Sessions */}
        <TabsContent value="sessions" className="mt-4">
          <ActiveSessionsTab />
        </TabsContent>

        <TabsContent value="secrets" className="mt-4 space-y-3">
          <Card className="border-border/30">
            <CardHeader className="py-3 px-4">
              <CardTitle className="text-sm flex items-center gap-2">
                <Key className="h-4 w-4 text-primary" />
                Managed Secrets Registry
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0 space-y-2">
              {secretsLoading ? (
                Array.from({ length: 4 }).map((_, i) => <Skeleton key={`secret-skeleton-${i}`} className="h-24" />)
              ) : filteredSecrets.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Key className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No secrets found</p>
                </div>
              ) : (
                filteredSecrets.map((secret: SecretCardProps["secret"]) => (
                  <SecretCard key={secret.id} secret={secret} />
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="requests" className="mt-4 space-y-3">
          <Card className="border-border/30">
            <CardHeader className="py-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <UserCheck className="h-4 w-4 text-primary" />
                  JIT Access Requests
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Badge
                    variant="outline"
                    className="text-[10px] bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                  >
                    {requestList.filter((r: { status: string }) => r.status === "pending").length} Pending
                  </Badge>
                  <Badge variant="outline" className="text-[10px] bg-green-500/20 text-green-400 border-green-500/30">
                    {
                      requestList.filter((r: { status: string }) => r.status === "active" || r.status === "approved")
                        .length
                    }{" "}
                    Active
                  </Badge>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-4 pt-0 space-y-2">
              {requestsLoading ? (
                Array.from({ length: 3 }).map((_, i) => <Skeleton key={`request-skeleton-${i}`} className="h-20" />)
              ) : filteredRequests.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <UserX className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No access requests</p>
                </div>
              ) : (
                filteredRequests.map((request: AccessRequestRowProps["request"]) => (
                  <AccessRequestRow key={request.id} request={request} />
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 28.3 Analytics */}
        <TabsContent value="analytics" className="mt-4">
          <AccessAnalyticsTab />
        </TabsContent>

        <TabsContent value="shares" className="mt-4 space-y-3">
          <Card className="border-border/30">
            <CardHeader className="py-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Send className="h-4 w-4 text-primary" />
                  One-Time External Shares
                </CardTitle>
                <Badge variant="outline" className="text-[10px] bg-green-500/20 text-green-400 border-green-500/30">
                  {shareList.filter((s: { status: string }) => s.status === "active").length} Active
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="p-4 pt-0 space-y-2">
              {sharesLoading ? (
                Array.from({ length: 2 }).map((_, i) => <Skeleton key={`share-skeleton-${i}`} className="h-24" />)
              ) : shareList.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Send className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No external shares</p>
                </div>
              ) : (
                shareList.map((share: ShareCardProps["share"]) => <ShareCard key={share.id} share={share} />)
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ownership" className="mt-4 space-y-3">
          <Card className="border-border/30">
            <CardHeader className="py-3 px-4">
              <CardTitle className="text-sm flex items-center gap-2">
                <ArrowRightLeft className="h-4 w-4 text-primary" />
                Ownership Transfers & Reclaims
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0 space-y-2">
              {transfersLoading ? (
                Array.from({ length: 2 }).map((_, i) => <Skeleton key={`transfer-skeleton-${i}`} className="h-24" />)
              ) : transferList.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <ArrowRightLeft className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No ownership transfers</p>
                </div>
              ) : (
                transferList.map((transfer: TransferCardProps["transfer"]) => (
                  <TransferCard key={transfer.id} transfer={transfer} />
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="break-glass" className="mt-4 space-y-3">
          <Card className="border-border/30">
            <CardHeader className="py-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Zap className="h-4 w-4 text-red-400" />
                  Break-Glass Emergency Access
                </CardTitle>
                {breakGlassList.filter(
                  (b: { retroactiveReviewRequired: boolean; status: string }) =>
                    b.retroactiveReviewRequired && b.status !== "reviewed",
                ).length > 0 && (
                  <Badge
                    variant="outline"
                    className="text-[10px] bg-red-500/20 text-red-400 border-red-500/30 animate-pulse"
                  >
                    <TriangleAlert className="h-3 w-3 mr-1" />
                    {
                      breakGlassList.filter(
                        (b: { retroactiveReviewRequired: boolean; status: string }) =>
                          b.retroactiveReviewRequired && b.status !== "reviewed",
                      ).length
                    }{" "}
                    Pending Reviews
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-4 pt-0 space-y-2">
              {breakGlassLoading ? (
                Array.from({ length: 2 }).map((_, i) => <Skeleton key={`bg-skeleton-${i}`} className="h-28" />)
              ) : breakGlassList.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No break-glass access events</p>
                </div>
              ) : (
                breakGlassList.map((entry: BreakGlassCardProps["entry"]) => (
                  <BreakGlassCard key={entry.id} entry={entry} />
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="audit" className="mt-4 space-y-3">
          <Card className="border-border/30">
            <CardHeader className="py-3 px-4">
              <CardTitle className="text-sm flex items-center gap-2">
                <ClipboardList className="h-4 w-4 text-primary" />
                Full Audit Trail
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              {auditLoading ? (
                Array.from({ length: 5 }).map((_, i) => <Skeleton key={`audit-skeleton-${i}`} className="h-12 mb-2" />)
              ) : auditList.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <ClipboardList className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No audit entries</p>
                </div>
              ) : (
                <div className="space-y-0.5 max-h-[600px] overflow-auto">
                  {[...auditList]
                    .sort(
                      (a: { timestamp: string }, b: { timestamp: string }) =>
                        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
                    )
                    .map((entry: AuditEntryRowProps["entry"], idx: number) => (
                      <AuditEntryRow key={`${entry.timestamp}-${idx}`} entry={entry} />
                    ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
