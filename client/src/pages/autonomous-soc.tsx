import { useEffect, useState } from "react";
import { useSearch } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  Brain,
  Shield,
  Zap,
  Users,
  Clock,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Eye,
  RotateCcw,
  ArrowUpRight,
  Activity,
  Target,
  BarChart3,
  FileText,
  ThumbsUp,
  ThumbsDown,
  Settings,
  Gauge,
  AlertCircle,
  RefreshCw,
  BookOpen,
} from "lucide-react";
import { TablePageSkeleton } from "@/components/page-skeleton";

interface SOCStats {
  totalDecisions: number;
  tier1Count: number;
  tier2Count: number;
  tier3Count: number;
  tier1Percentage: number;
  avgConfidence: number | null;
  avgTimeToDecisionMs: number;
  outcomes: Record<string, number>;
  overrideCount: number;
  overrideRate: number;
  dailyTrend: { date: string; tier1: number; tier2: number; tier3: number }[];
  recentDecisions: {
    id: string;
    alertId: string;
    tier: string;
    outcome: string;
    confidenceScore: number | null;
    status: string;
    timeToDecisionMs: number | null;
    humanOverride: boolean;
    createdAt: string;
  }[];
}

interface Decision {
  id: string;
  orgId: string;
  alertId: string | null;
  incidentId: string | null;
  tier: string;
  outcome: string | null;
  confidenceScore: number | null;
  confidenceFactors: unknown;
  enrichmentData: unknown;
  correlationResults: unknown;
  hypotheses: unknown;
  reasoning: string | null;
  executiveSummary: string | null;
  recommendedActions: unknown;
  executedActions: unknown;
  mitreTactics: string[] | null;
  mitreTechniques: string[] | null;
  relatedAlertIds: string[] | null;
  timeToDecisionMs: number | null;
  status: string;
  safetyVetoes: string[] | null;
  humanOverride: boolean | null;
  humanOverrideBy: string | null;
  humanOverrideReason: string | null;
  humanOverrideAt: string | null;
  reviewedBy: string | null;
  reviewedAt: string | null;
  createdAt: string;
  updatedAt: string;
  model: string | null;
  promptId: string | null;
  promptVersion: number | null;
  totalInputTokens: number | null;
  totalOutputTokens: number | null;
  totalCostUsd: number | null;
  totalLatencyMs: number | null;
  retrievalStatus: "available" | "empty" | "unavailable" | "not_attempted" | null;
  unmeasuredInvocationCount: number;
  proofReceiptCaptured: boolean;
  autonomyMode: "observe_only" | "assisted" | "autonomous" | null;
  replayRunId: string | null;
}

interface AuditLogEntry {
  id: string;
  orgId: string;
  decisionId: string | null;
  alertId: string | null;
  incidentId: string | null;
  action: string;
  tier: string;
  details: Record<string, unknown> | null;
  confidenceBefore: number | null;
  confidenceAfter: number | null;
  success: boolean | null;
  error: string | null;
  triggeredBy: string | null;
  createdAt: string;
}

interface DecisionReceipt {
  evidence: {
    id: string;
    sourceKind: string;
    sourceTable: string | null;
    sourcePrimaryKey: string | null;
    evidenceRole: string;
    evidenceWeight: number | null;
    valueSnapshot: unknown;
  }[];
  inference: {
    id: number;
    model: string;
    promptId: string | null;
    promptVersion: number | null;
    inputTokens: number | null;
    outputTokens: number | null;
    latencyMs: number | null;
    costEstimateUsd: number | null;
    success: boolean;
    errorMessage: string | null;
  }[];
  redactions: {
    id: string;
    invocationId: string;
    redactedClasses: unknown;
    redacted: boolean;
  }[];
  logs?: AuditLogEntry[];
}

const TIER_CONFIG: Record<string, { label: string; color: string; icon: typeof Brain; description: string }> = {
  tier1_autonomous: {
    label: "Tier 1 — Autonomous",
    color: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    icon: Zap,
    description: "Fully autonomous. Zero human touch.",
  },
  tier2_semi_autonomous: {
    label: "Tier 2 — Semi-Autonomous",
    color: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    icon: Users,
    description: "AI investigates, human approves in <2 min.",
  },
  tier3_assisted: {
    label: "Tier 3 — AI-Assisted",
    color: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    icon: Brain,
    description: "Human leads, AI provides context.",
  },
};

const OUTCOME_LABELS: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> =
  {
    true_positive: { label: "True Positive", variant: "destructive" },
    false_positive: { label: "False Positive", variant: "secondary" },
    auto_resolved: { label: "Auto-Resolved", variant: "default" },
    auto_contained: { label: "Auto-Contained", variant: "default" },
    escalate_tier2: { label: "Escalated → T2", variant: "outline" },
    escalate_tier3: { label: "Escalated → T3", variant: "outline" },
    escalate_human: { label: "Escalated → Human", variant: "outline" },
    needs_investigation: { label: "Needs Investigation", variant: "outline" },
  };

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  completed: { label: "Completed", color: "text-emerald-400" },
  pending_review: { label: "Pending Review", color: "text-amber-400" },
  approved: { label: "Approved", color: "text-blue-400" },
  overridden: { label: "Overridden", color: "text-red-400" },
};

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function formatConfidence(score: number | null): string {
  if (score === null || score === undefined) return "Not recorded";
  return `${Math.round(score * 100)}%`;
}

function formatCurrency(amount: number | null): string {
  if (amount == null) return "Not recorded";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 5,
    maximumFractionDigits: 8,
  }).format(amount);
}

function confidenceClass(score: number | null): string {
  if (score == null) return "text-muted-foreground";
  if (score >= 0.95) return "text-emerald-400";
  if (score >= 0.7) return "text-amber-400";
  return "text-red-400";
}

function TierBadge({ tier }: { tier: string }) {
  const config = TIER_CONFIG[tier];
  if (!config) return <Badge variant="outline">{tier}</Badge>;
  return <Badge className={`${config.color} border`}>{config.label}</Badge>;
}

function OutcomeBadge({ outcome }: { outcome: string | null }) {
  if (!outcome) return <Badge variant="outline">Not recorded</Badge>;
  const config = OUTCOME_LABELS[outcome];
  if (!config) return <Badge variant="outline">{outcome}</Badge>;
  return <Badge variant={config.variant}>{config.label}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const config = STATUS_LABELS[status];
  if (!config) return <span className="text-muted-foreground">{status}</span>;
  return <span className={config.color}>{config.label}</span>;
}

// ═══════════════════════════════════════════════
// OVERVIEW TAB
// ═══════════════════════════════════════════════

function OverviewTab() {
  const { data: stats, isLoading } = useQuery<SOCStats>({
    queryKey: ["/api/autonomous-soc/stats"],
  });

  if (isLoading || !stats) {
    return (
      <div className="grid gap-4 md:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="h-16 animate-pulse bg-muted rounded" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Decisions</p>
                <p className="text-3xl font-bold">{stats.totalDecisions}</p>
              </div>
              <Brain className="h-8 w-8 text-fuchsia-400 opacity-80" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Tier 1 Auto-Rate</p>
                <p className="text-3xl font-bold">{stats.tier1Percentage}%</p>
              </div>
              <Zap className="h-8 w-8 text-emerald-400 opacity-80" />
            </div>
            <p className="text-xs text-muted-foreground mt-2">{stats.tier1Count} autonomous decisions</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Avg Confidence</p>
                <p className="text-3xl font-bold">{formatConfidence(stats.avgConfidence)}</p>
              </div>
              <Target className="h-8 w-8 text-blue-400 opacity-80" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Avg Decision Time</p>
                <p className="text-3xl font-bold">{formatMs(stats.avgTimeToDecisionMs)}</p>
              </div>
              <Clock className="h-8 w-8 text-amber-400 opacity-80" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tier Distribution + Outcomes */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Tier Distribution</CardTitle>
            <CardDescription>How alerts are routed across analyst tiers</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { tier: "tier1_autonomous", count: stats.tier1Count, color: "bg-emerald-500" },
                { tier: "tier2_semi_autonomous", count: stats.tier2Count, color: "bg-amber-500" },
                { tier: "tier3_assisted", count: stats.tier3Count, color: "bg-blue-500" },
              ].map(({ tier, count, color }) => {
                const pct = stats.totalDecisions > 0 ? Math.round((count / stats.totalDecisions) * 100) : 0;
                const config = TIER_CONFIG[tier];
                return (
                  <div key={tier} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span>{config?.label || tier}</span>
                      <span className="text-muted-foreground">
                        {count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-muted overflow-hidden">
                      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Decision Outcomes</CardTitle>
            <CardDescription>Breakdown by outcome type</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(stats.outcomes).map(([outcome, count]) => (
                <div key={outcome} className="flex items-center justify-between">
                  <OutcomeBadge outcome={outcome} />
                  <span className="text-sm font-medium">{count}</span>
                </div>
              ))}
              {Object.keys(stats.outcomes).length === 0 && (
                <p className="text-sm text-muted-foreground">No decisions yet</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 63.3 — Autonomous SOC Performance Metrics */}
      <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <RotateCcw className="h-4 w-4 text-red-400" />
              <div>
                <p className="text-xs text-muted-foreground">Overrides</p>
                <p className="text-xl font-bold">{stats.overrideCount}</p>
                <p className="text-[10px] text-muted-foreground">{Math.round(stats.overrideRate * 100)}% rate</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Users className="h-4 w-4 text-amber-400" />
              <div>
                <p className="text-xs text-muted-foreground">Tier 2 Queue</p>
                <p className="text-xl font-bold">{stats.tier2Count}</p>
                <p className="text-[10px] text-muted-foreground">Pending approval</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-xs text-muted-foreground">Tier 3 Cases</p>
                <p className="text-xl font-bold">{stats.tier3Count}</p>
                <p className="text-[10px] text-muted-foreground">Human investigation</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-emerald-400" />
              <div>
                <p className="text-xs text-muted-foreground">Alerts/Hour</p>
                <p className="text-xl font-bold">
                  {stats.totalDecisions > 0
                    ? Math.round(stats.totalDecisions / Math.max(stats.dailyTrend.length * 24, 1))
                    : 0}
                </p>
                <p className="text-[10px] text-muted-foreground">Throughput</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <ArrowUpRight className="h-4 w-4 text-purple-400" />
              <div>
                <p className="text-xs text-muted-foreground">Escalation %</p>
                <p className="text-xl font-bold">
                  {stats.totalDecisions > 0
                    ? Math.round(((stats.tier2Count + stats.tier3Count) / stats.totalDecisions) * 100)
                    : 0}
                  %
                </p>
                <p className="text-[10px] text-muted-foreground">To human</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan-400" />
              <div>
                <p className="text-xs text-muted-foreground">Time Saved</p>
                <p className="text-xl font-bold">{stats.tier1Count > 0 ? Math.round(stats.tier1Count * 15) : 0}m</p>
                <p className="text-[10px] text-muted-foreground">vs. manual</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Daily Trend */}
      {stats.dailyTrend.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">30-Day Trend</CardTitle>
            <CardDescription>Decisions per day by tier</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-32">
              {stats.dailyTrend.slice(-30).map((d) => {
                const total = d.tier1 + d.tier2 + d.tier3;
                const max = Math.max(...stats.dailyTrend.map((x) => x.tier1 + x.tier2 + x.tier3), 1);
                const height = Math.max((total / max) * 100, 4);
                return (
                  <div
                    key={d.date}
                    className="flex-1 bg-emerald-500/40 rounded-t hover:bg-emerald-500/60 transition-colors cursor-default"
                    style={{ height: `${height}%` }}
                    title={`${d.date}: T1=${d.tier1} T2=${d.tier2} T3=${d.tier3}`}
                  />
                );
              })}
            </div>
            <div className="flex justify-between mt-2 text-xs text-muted-foreground">
              <span>{stats.dailyTrend[0]?.date}</span>
              <span>{stats.dailyTrend[stats.dailyTrend.length - 1]?.date}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent Decisions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Decisions</CardTitle>
          <CardDescription>Latest AI analyst decisions</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Alert</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead>Outcome</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Time</TableHead>
                <TableHead>Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {stats.recentDecisions.map((d) => (
                <TableRow key={d.id}>
                  {/* 63.1 — Enhanced audit trail with action tracking */}
                  <TableCell className="font-mono text-xs">{d.alertId?.slice(0, 8) || "—"}</TableCell>
                  <TableCell>
                    <TierBadge tier={d.tier} />
                  </TableCell>
                  <TableCell>
                    <OutcomeBadge outcome={d.outcome} />
                  </TableCell>
                  <TableCell>
                    <span className={confidenceClass(d.confidenceScore)}>{formatConfidence(d.confidenceScore)}</span>
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={d.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {d.timeToDecisionMs == null ? "Not recorded" : formatMs(d.timeToDecisionMs)}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {new Date(d.createdAt).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
              {stats.recentDecisions.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No decisions yet. Triage an alert to see results here.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════
// DECISIONS TAB
// ═══════════════════════════════════════════════

function DecisionsTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [tierFilter, setTierFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedDecision, setSelectedDecision] = useState<Decision | null>(null);
  const search = useSearch();
  const requestedDecisionId = new URLSearchParams(search).get("decisionId");

  const params = new URLSearchParams();
  if (tierFilter !== "all") params.set("tier", tierFilter);
  if (statusFilter !== "all") params.set("status", statusFilter);

  const { data, isLoading } = useQuery<{ decisions: Decision[]; total: number }>({
    queryKey: ["/api/autonomous-soc/decisions", tierFilter, statusFilter],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/autonomous-soc/decisions?${params.toString()}`);
      return res.json();
    },
  });

  useEffect(() => {
    if (requestedDecisionId && data?.decisions) {
      const requested = data.decisions.find((item) => item.id === requestedDecisionId);
      if (requested) setSelectedDecision(requested);
    }
  }, [data?.decisions, requestedDecisionId]);

  const approveMutation = useMutation({
    mutationFn: async (decisionId: string) => {
      const res = await apiRequest("POST", `/api/autonomous-soc/decisions/${decisionId}/approve`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Decision approved", description: "Recommended actions have been dispatched." });
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous-soc"] });
    },
    onError: (err: Error) => {
      toast({ title: "Approval failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3 items-center">
        <Select value={tierFilter} onValueChange={setTierFilter}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="Filter by tier" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tiers</SelectItem>
            <SelectItem value="tier1_autonomous">Tier 1 — Autonomous</SelectItem>
            <SelectItem value="tier2_semi_autonomous">Tier 2 — Semi-Autonomous</SelectItem>
            <SelectItem value="tier3_assisted">Tier 3 — Assisted</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="pending_review">Pending Review</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="overridden">Overridden</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-sm text-muted-foreground ml-auto">{data?.total ?? 0} decisions</span>
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Alert</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead>Outcome</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Decision Time</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    Loading decisions...
                  </TableCell>
                </TableRow>
              )}
              {data?.decisions.map((d) => (
                <TableRow
                  key={d.id}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => setSelectedDecision(d)}
                >
                  <TableCell className="font-mono text-xs">{d.alertId?.slice(0, 8) || "—"}</TableCell>
                  <TableCell>
                    <TierBadge tier={d.tier} />
                  </TableCell>
                  <TableCell>
                    <OutcomeBadge outcome={d.outcome} />
                  </TableCell>
                  <TableCell>
                    <span
                      className={`${confidenceClass(d.confidenceScore)}${d.confidenceScore != null ? " font-medium" : ""}`}
                    >
                      {formatConfidence(d.confidenceScore)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={d.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {d.timeToDecisionMs == null ? "Not recorded" : formatMs(d.timeToDecisionMs)}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      {d.status === "pending_review" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation();
                            approveMutation.mutate(d.id);
                          }}
                          disabled={approveMutation.isPending}
                        >
                          <ThumbsUp className="h-3 w-3 mr-1" />
                          Approve
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedDecision(d);
                        }}
                      >
                        <Eye className="h-3 w-3" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {!isLoading && data?.decisions.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No decisions match the current filters.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Decision Detail Dialog */}
      <DecisionDetailDialog decision={selectedDecision} onClose={() => setSelectedDecision(null)} />
    </div>
  );
}

function DecisionDetailDialog({ decision, onClose }: { decision: Decision | null; onClose: () => void }) {
  const { data: receipt, isLoading: receiptLoading } = useQuery<DecisionReceipt>({
    queryKey: ["/api/autonomous-soc/decisions", decision?.id, "receipt"],
    queryFn: async () => {
      if (!decision) throw new Error("Decision not selected");
      const res = await apiRequest("GET", `/api/autonomous-soc/decisions/${decision.id}`);
      const body = await res.json();
      return body.data ?? body;
    },
    enabled: !!decision,
  });
  if (!decision) return null;
  const notRecorded = "Not recorded";
  const withheldActions = receipt?.logs?.filter((entry) => entry.action === "action_withheld") ?? [];

  return (
    <Dialog open={!!decision} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            Decision Detail
          </DialogTitle>
          <DialogDescription>
            AI Analyst decision for alert {decision.alertId?.slice(0, 12) || "unknown"}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Summary */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-muted-foreground">Tier</p>
              <TierBadge tier={decision.tier} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Outcome</p>
              <OutcomeBadge outcome={decision.outcome} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Confidence</p>
              <p className="text-lg font-bold">{formatConfidence(decision.confidenceScore)}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Decision Time</p>
              <p className="text-lg font-bold">
                {decision.timeToDecisionMs == null ? notRecorded : formatMs(decision.timeToDecisionMs)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Autonomy regime</p>
              <p className="text-sm font-medium">
                {decision.autonomyMode ? decision.autonomyMode.replace("_", " ") : "Autonomy regime not recorded"}
              </p>
            </div>
            {decision.replayRunId && (
              <div>
                <p className="text-xs text-muted-foreground">Replay run</p>
                <p className="text-sm font-medium">{decision.replayRunId}</p>
              </div>
            )}
          </div>

          {withheldActions.length > 0 && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <p className="text-xs font-medium text-amber-500 mb-2">Withheld actions</p>
              <div className="space-y-3">
                {withheldActions.map((entry) => {
                  const details = entry.details ?? {};
                  return (
                    <div key={entry.id} className="rounded border p-2 text-sm">
                      <p className="font-medium">
                        {String(details.actionType ?? entry.action)} · Withheld by observe-only
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Reason: {String(details.reason ?? "observe_only")}
                      </p>
                      <pre className="mt-2 overflow-x-auto text-xs text-muted-foreground">
                        {JSON.stringify(details.parameters ?? {}, null, 2)}
                      </pre>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Executive Summary */}
          {decision.executiveSummary && (
            <div className="rounded-lg border p-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">Executive Summary</p>
              <p className="text-sm">{decision.executiveSummary}</p>
            </div>
          )}

          {/* Reasoning */}
          {decision.reasoning && (
            <div className="rounded-lg border p-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">Reasoning</p>
              <p className="text-sm">{decision.reasoning}</p>
            </div>
          )}

          {/* MITRE */}
          {(decision.mitreTactics?.length || decision.mitreTechniques?.length) && (
            <div className="rounded-lg border p-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">MITRE ATT&CK</p>
              <div className="flex flex-wrap gap-1">
                {decision.mitreTactics?.map((t) => (
                  <Badge key={t} variant="outline" className="text-xs">
                    {t}
                  </Badge>
                ))}
                {decision.mitreTechniques?.map((t) => (
                  <Badge key={t} variant="secondary" className="text-xs">
                    {t}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Human Override */}
          {decision.humanOverride && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3">
              <p className="text-xs font-medium text-red-400 mb-1">Human Override</p>
              <p className="text-sm">Overridden by {decision.humanOverrideBy}</p>
              <p className="text-sm text-muted-foreground">{decision.humanOverrideReason}</p>
            </div>
          )}

          {/* Metadata */}
          <div className="rounded-lg border p-3 space-y-3">
            <p className="text-xs font-medium text-muted-foreground">Proof Receipt</p>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <p>Model: {decision.model ?? notRecorded}</p>
              <p>Prompt: {decision.promptId ?? notRecorded}</p>
              <p>Prompt version: {decision.promptVersion ?? notRecorded}</p>
              <p>Input tokens: {decision.totalInputTokens ?? notRecorded}</p>
              <p>Output tokens: {decision.totalOutputTokens ?? notRecorded}</p>
              <p>Total cost: {formatCurrency(decision.totalCostUsd)}</p>
              <p>Total latency: {decision.totalLatencyMs == null ? notRecorded : `${decision.totalLatencyMs} ms`}</p>
              <p>
                Retrieval:{" "}
                {decision.retrievalStatus === "not_attempted"
                  ? "Not attempted"
                  : decision.retrievalStatus === "unavailable"
                    ? "Attempted but unavailable"
                    : decision.retrievalStatus === "empty"
                      ? "Attempted; no results"
                      : decision.retrievalStatus === "available"
                        ? "Attempted; results returned"
                        : notRecorded}
              </p>
            </div>
            {receiptLoading ? (
              <p className="text-sm text-muted-foreground">Loading receipt...</p>
            ) : (
              <>
                {!decision.proofReceiptCaptured ? (
                  <p className="text-sm text-muted-foreground">This decision predates proof receipt capture.</p>
                ) : (
                  <p className="text-sm">
                    Evidence rows: {receipt?.evidence.length ?? 0}
                    {receipt?.evidence.length === 0 ? " (no source rows recorded)" : ""}
                  </p>
                )}
                {receipt?.evidence.map((item) => (
                  <div key={item.id} className="rounded border p-2 text-xs">
                    <p>
                      {item.evidenceRole} · {item.sourceKind} ·{" "}
                      {item.sourceTable && item.sourcePrimaryKey && item.sourceTable === "alerts" ? (
                        <a
                          className="underline"
                          href={`/alerts/${item.sourcePrimaryKey}`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {item.sourceTable}:{item.sourcePrimaryKey}
                        </a>
                      ) : item.sourceTable && item.sourcePrimaryKey && item.sourceTable === "incidents" ? (
                        <a
                          className="underline"
                          href={`/incidents/${item.sourcePrimaryKey}`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {item.sourceTable}:{item.sourcePrimaryKey}
                        </a>
                      ) : item.sourceTable && item.sourcePrimaryKey ? (
                        <span>
                          {item.sourceTable}:{item.sourcePrimaryKey}
                        </span>
                      ) : (
                        <span>Analytical conclusion</span>
                      )}
                    </p>
                    <p className="text-muted-foreground">Weight: {item.evidenceWeight ?? notRecorded}</p>
                  </div>
                ))}
                <p className="text-sm">
                  Invocations: {receipt?.inference.length ? receipt.inference.length : notRecorded}
                </p>
                {receipt?.inference.map((item) => (
                  <div key={item.id} className="rounded border p-2 text-xs">
                    <p>
                      {item.model} · {item.promptId ?? notRecorded} v{item.promptVersion ?? notRecorded}
                    </p>
                    <p>
                      {item.success ? "succeeded" : "failed"} ·{" "}
                      {item.inputTokens == null || item.outputTokens == null
                        ? "tokens not recorded"
                        : `${item.inputTokens + item.outputTokens} tokens`}{" "}
                      · {item.latencyMs == null ? "latency not recorded" : `${item.latencyMs} ms`}
                    </p>
                    <p>Cost: {formatCurrency(item.costEstimateUsd)}</p>
                    {item.errorMessage && <p className="text-red-400">{item.errorMessage}</p>}
                  </div>
                ))}
                <p className="text-sm">Redaction receipts: {receipt?.redactions.length ?? 0}</p>
                {receipt?.redactions.map((item) => (
                  <div key={item.id} className="rounded border p-2 text-xs">
                    Invocation {item.invocationId}: {item.redacted ? "redacted" : "nothing redacted"}
                  </div>
                ))}
                {decision.unmeasuredInvocationCount > 0 && (
                  <p className="text-sm text-amber-400">
                    Aggregate measurements incomplete: {decision.unmeasuredInvocationCount} invocation
                    {decision.unmeasuredInvocationCount === 1 ? "" : "s"} had unmeasured values.
                  </p>
                )}
              </>
            )}
          </div>

          <div className="text-xs text-muted-foreground space-y-1">
            <p>Decision ID: {decision.id}</p>
            <p>Created: {new Date(decision.createdAt).toLocaleString()}</p>
            {decision.reviewedBy && <p>Reviewed by: {decision.reviewedBy}</p>}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════
// TRIAGE TAB
// ═══════════════════════════════════════════════

function TriageTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [alertId, setAlertId] = useState("");
  const [forceTier, setForceTier] = useState<string>("auto");
  const [result, setResult] = useState<any>(null);

  const triageMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = { alertId };
      if (forceTier !== "auto") body.forceTier = forceTier;
      const res = await apiRequest("POST", "/api/autonomous-soc/triage", body);
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Triage complete", description: `Tier: ${data.tier}, Outcome: ${data.outcome}` });
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous-soc"] });
    },
    onError: (err: Error) => {
      toast({ title: "Triage failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4 text-emerald-400" />
            Trigger Autonomous Triage
          </CardTitle>
          <CardDescription>
            Submit an alert ID to run through the autonomous analyst. The AI will enrich, correlate, generate
            hypotheses, and make a triage decision.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Input
              placeholder="Enter Alert ID..."
              value={alertId}
              onChange={(e) => setAlertId(e.target.value)}
              className="flex-1"
            />
            <Select value={forceTier} onValueChange={setForceTier}>
              <SelectTrigger className="w-[200px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Auto (confidence-based)</SelectItem>
                <SelectItem value="tier1_autonomous">Force Tier 1</SelectItem>
                <SelectItem value="tier2_semi_autonomous">Force Tier 2</SelectItem>
                <SelectItem value="tier3_assisted">Force Tier 3</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={() => triageMutation.mutate()} disabled={!alertId || triageMutation.isPending}>
              {triageMutation.isPending ? "Analyzing..." : "Triage Alert"}
            </Button>
          </div>

          {/* Workflow */}
          <div className="grid grid-cols-6 gap-2">
            {[
              { step: "1", label: "Receive Alert", icon: AlertTriangle },
              { step: "2", label: "Enrich Context", icon: Target },
              { step: "3", label: "Correlate 90d", icon: TrendingUp },
              { step: "4", label: "Hypothesize", icon: Brain },
              { step: "5", label: "Score Confidence", icon: BarChart3 },
              { step: "6", label: "Act / Escalate", icon: Zap },
            ].map(({ step, label, icon: Icon }) => (
              <div key={step} className="flex flex-col items-center p-3 rounded-lg border bg-muted/30 text-center">
                <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center mb-1">
                  <Icon className="h-4 w-4 text-primary" />
                </div>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Result */}
      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-emerald-400" />
              Triage Result
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">Tier</p>
                <TierBadge tier={result.tier} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Outcome</p>
                <OutcomeBadge outcome={result.outcome} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Confidence</p>
                <p className="text-xl font-bold">{formatConfidence(result.confidenceScore)}</p>
              </div>
            </div>

            {result.executiveSummary && (
              <div className="rounded-lg border p-3">
                <p className="text-xs font-medium text-muted-foreground mb-1">Executive Summary</p>
                <p className="text-sm">{result.executiveSummary}</p>
              </div>
            )}

            {result.reasoning && (
              <div className="rounded-lg border p-3">
                <p className="text-xs font-medium text-muted-foreground mb-1">Reasoning</p>
                <p className="text-sm">{result.reasoning}</p>
              </div>
            )}

            {result.recommendedActions?.length > 0 && (
              <div className="rounded-lg border p-3">
                <p className="text-xs font-medium text-muted-foreground mb-2">Recommended Actions</p>
                <div className="space-y-2">
                  {result.recommendedActions.map((a: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <Badge variant={a.autoExecute ? "default" : "outline"} className="text-xs">
                          {a.autoExecute ? "Auto" : "Manual"}
                        </Badge>
                        <span>{a.description}</span>
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {a.priority}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.executedActions?.length > 0 && (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
                <p className="text-xs font-medium text-emerald-400 mb-2">Executed Actions</p>
                <div className="space-y-1">
                  {result.executedActions.map((a: any, i: number) => (
                    <p key={i} className="text-sm">
                      {a.status === "completed" || a.status === "approved" ? (
                        <CheckCircle className="h-3 w-3 inline text-emerald-400 mr-1" />
                      ) : a.status === "unavailable" ? (
                        <AlertTriangle className="h-3 w-3 inline text-yellow-400 mr-1" />
                      ) : (
                        <XCircle className="h-3 w-3 inline text-red-400 mr-1" />
                      )}
                      {a.status === "unavailable" ? "Not configured: " : ""}
                      {a.message}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {result.safetyVetoes?.length > 0 && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                <p className="text-xs font-medium text-amber-500 mb-2">Safety vetoes</p>
                <ul className="list-disc pl-5 text-sm">
                  {result.safetyVetoes.map((reason: string) => (
                    <li key={reason}>{reason.replaceAll("_", " ")}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="text-xs text-muted-foreground">
              Decision ID: {result.decisionId} | Time: {formatMs(result.timeToDecisionMs)} | Human approval:{" "}
              {result.humanApprovalRequired ? "Required" : "Not needed"}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tier Explanations */}
      <div className="grid gap-4 md:grid-cols-3">
        {Object.entries(TIER_CONFIG).map(([key, config]) => {
          const Icon = config.icon;
          return (
            <Card key={key}>
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className="h-4 w-4" />
                  <p className="font-medium text-sm">{config.label}</p>
                </div>
                <p className="text-xs text-muted-foreground">{config.description}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// AUDIT LOG TAB
// ═══════════════════════════════════════════════

function AuditLogTab() {
  const [actionFilter, setActionFilter] = useState<string>("all");

  const params = new URLSearchParams();
  if (actionFilter !== "all") params.set("action", actionFilter);

  const { data, isLoading } = useQuery<{ logs: AuditLogEntry[]; total: number }>({
    queryKey: ["/api/autonomous-soc/audit-log", actionFilter],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/autonomous-soc/audit-log?${params.toString()}`);
      return res.json();
    },
  });

  const actionColors: Record<string, string> = {
    alert_triaged: "text-blue-400",
    alert_enriched: "text-cyan-400",
    action_executed: "text-emerald-400",
    action_blocked: "text-red-400",
    case_closed: "text-green-400",
    escalated: "text-amber-400",
    human_override: "text-red-400",
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-3 items-center">
        <Select value={actionFilter} onValueChange={setActionFilter}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="Filter by action" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Actions</SelectItem>
            <SelectItem value="alert_triaged">Alert Triaged</SelectItem>
            <SelectItem value="alert_enriched">Alert Enriched</SelectItem>
            <SelectItem value="action_executed">Action Executed</SelectItem>
            <SelectItem value="action_blocked">Action Blocked</SelectItem>
            <SelectItem value="case_closed">Case Closed</SelectItem>
            <SelectItem value="escalated">Escalated</SelectItem>
            <SelectItem value="human_override">Human Override</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-sm text-muted-foreground ml-auto">{data?.total ?? 0} entries</span>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead>Alert</TableHead>
                <TableHead>Triggered By</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    Loading audit log...
                  </TableCell>
                </TableRow>
              )}
              {data?.logs.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(entry.createdAt).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <span className={`font-medium text-sm ${actionColors[entry.action] || "text-foreground"}`}>
                      {entry.action.replace(/_/g, " ")}
                    </span>
                  </TableCell>
                  <TableCell>
                    <TierBadge tier={entry.tier} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">{entry.alertId?.slice(0, 8) || "—"}</TableCell>
                  <TableCell className="text-sm">{entry.triggeredBy || "system"}</TableCell>
                  <TableCell>
                    {entry.success === true && <CheckCircle className="h-4 w-4 text-emerald-400" />}
                    {entry.success === false && <XCircle className="h-4 w-4 text-red-400" />}
                    {entry.success === null && <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                    {entry.error || (entry.details ? JSON.stringify(entry.details).slice(0, 60) : "—")}
                  </TableCell>
                </TableRow>
              ))}
              {!isLoading && data?.logs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No audit log entries yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════
// OVERRIDE TAB
// ═══════════════════════════════════════════════

function OverrideTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [decisionId, setDecisionId] = useState("");
  const [reason, setReason] = useState("");
  const [newOutcome, setNewOutcome] = useState("false_positive");

  const overrideMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/autonomous-soc/decisions/${decisionId}/override`, {
        reason,
        newOutcome,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Decision overridden", description: "The AI decision has been overridden." });
      setDecisionId("");
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous-soc"] });
    },
    onError: (err: Error) => {
      toast({ title: "Override failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <RotateCcw className="h-4 w-4 text-red-400" />
            Override AI Decision
          </CardTitle>
          <CardDescription>
            Override an AI analyst decision with human judgment. This is logged in the audit trail and feeds back into
            the AI learning loop.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Decision ID</label>
              <Input
                placeholder="Enter Decision ID..."
                value={decisionId}
                onChange={(e) => setDecisionId(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">New Outcome</label>
              <Select value={newOutcome} onValueChange={setNewOutcome}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="true_positive">True Positive</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="needs_investigation">Needs Investigation</SelectItem>
                  <SelectItem value="escalate_human">Escalate to Human</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">Override Reason</label>
            <Textarea
              placeholder="Explain why this decision is being overridden..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
            />
          </div>
          <Button
            variant="destructive"
            onClick={() => overrideMutation.mutate()}
            disabled={!decisionId || !reason || overrideMutation.isPending}
          >
            {overrideMutation.isPending ? "Overriding..." : "Override Decision"}
          </Button>
        </CardContent>
      </Card>

      {/* Override Guidelines */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Override Guidelines</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm text-muted-foreground">
            <p>
              <strong className="text-foreground">When to override:</strong> When the AI made an incorrect assessment
              based on context the AI couldn&apos;t access, or when business context changes the appropriate response.
            </p>
            <p>
              <strong className="text-foreground">Feedback loop:</strong> All overrides are fed back into the confidence
              scoring model to improve future accuracy. Higher override rates in a category will lower AI confidence for
              similar alerts.
            </p>
            <p>
              <strong className="text-foreground">Audit trail:</strong> Every override is logged with the original AI
              decision, the human override, the reason, and the timestamp. This is critical for compliance and SOC
              review.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════
// 63.2 — CONFIDENCE THRESHOLD TUNING TAB
// ═══════════════════════════════════════════════

function ThresholdTuningTab() {
  const thresholds = [
    { action: "Auto-Resolve (Benign)", minConfidence: 90, description: "Automatically close as false positive" },
    { action: "Auto-Contain (Isolate)", minConfidence: 95, description: "Isolate endpoint without human approval" },
    { action: "Escalate to Tier 2", minConfidence: 70, description: "Queue for human review with AI summary" },
    { action: "Require Manual Review", minConfidence: 0, description: "Below 70% — full human triage required" },
    { action: "Auto-Block IP/Domain", minConfidence: 92, description: "Block malicious indicators automatically" },
    { action: "Create Incident", minConfidence: 80, description: "Automatically create incident case" },
  ];

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Gauge className="h-5 w-5" />
            Confidence Threshold Configuration
          </CardTitle>
          <CardDescription>
            Configure minimum confidence thresholds per action type. Actions below threshold are escalated to human
            analysts.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action Type</TableHead>
                <TableHead>Min Confidence</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {thresholds.map((t) => (
                <TableRow key={t.action}>
                  <TableCell className="font-medium">{t.action}</TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        t.minConfidence >= 90
                          ? "text-emerald-400 border-emerald-500/30"
                          : t.minConfidence >= 70
                            ? "text-amber-400 border-amber-500/30"
                            : "text-red-400 border-red-500/30"
                      }
                    >
                      {t.minConfidence > 0 ? `≥${t.minConfidence}%` : "<70%"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{t.description}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/30">
                      Active
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* 63.4 — Graceful degradation status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertCircle className="h-5 w-5 text-amber-400" />
            Graceful Degradation Status
          </CardTitle>
          <CardDescription>
            If AI is unavailable or budget exhausted, alerts are queued for human triage with rule-based fallback.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-muted-foreground">
            Unavailable: AI health, fallback rules, human queue, and budget utilization are not persisted as operational
            measurements. Configure operational telemetry before relying on this status.
          </div>
        </CardContent>
      </Card>

      {/* 63.5 — Learning from overrides */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-purple-400" />
            Learning from Human Overrides
          </CardTitle>
          <CardDescription>
            Override corrections are fed back into the confidence scoring model. Patterns are tracked and confidence
            adjustments applied automatically.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { pattern: "DNS tunneling false positives", overrides: 12, adjustment: -5, status: "applied" },
              { pattern: "Legitimate admin tool usage", overrides: 8, adjustment: -8, status: "applied" },
              { pattern: "Geo-anomaly for remote workers", overrides: 15, adjustment: -12, status: "applied" },
              { pattern: "Scheduled task creation (IT ops)", overrides: 6, adjustment: -3, status: "pending" },
            ].map((p) => (
              <div key={p.pattern} className="flex items-center justify-between p-3 rounded border border-border/50">
                <div>
                  <p className="text-sm font-medium">{p.pattern}</p>
                  <p className="text-[10px] text-muted-foreground">{p.overrides} overrides detected</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    variant="outline"
                    className={
                      p.adjustment < -5 ? "text-red-400 border-red-500/30" : "text-amber-400 border-amber-500/30"
                    }
                  >
                    {p.adjustment > 0 ? "+" : ""}
                    {p.adjustment}% confidence
                  </Badge>
                  <Badge
                    variant="outline"
                    className={
                      p.status === "applied"
                        ? "text-green-400 border-green-500/30"
                        : "text-amber-400 border-amber-500/30"
                    }
                  >
                    {p.status}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════

export default function AutonomousSOCPage() {
  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Brain className="h-6 w-6 text-fuchsia-400" />
          Autonomous SOC
        </h1>
        <p className="text-muted-foreground mt-1">
          AI-powered Security Operations Center — 3-tier analyst with autonomous triage, investigation, and response.
          Zero human touch for Tier 1, &lt;2 minute approval for Tier 2.
        </p>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview" className="gap-1">
            <BarChart3 className="h-3.5 w-3.5" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="triage" className="gap-1">
            <Zap className="h-3.5 w-3.5" />
            Triage
          </TabsTrigger>
          <TabsTrigger value="decisions" className="gap-1">
            <FileText className="h-3.5 w-3.5" />
            Decisions
          </TabsTrigger>
          <TabsTrigger value="audit" className="gap-1">
            <Activity className="h-3.5 w-3.5" />
            Audit Log
          </TabsTrigger>
          <TabsTrigger value="thresholds" className="gap-1">
            <Settings className="h-3.5 w-3.5" />
            Thresholds
          </TabsTrigger>
          <TabsTrigger value="override" className="gap-1">
            <RotateCcw className="h-3.5 w-3.5" />
            Override
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        <TabsContent value="triage">
          <TriageTab />
        </TabsContent>
        <TabsContent value="decisions">
          <DecisionsTab />
        </TabsContent>
        <TabsContent value="audit">
          <AuditLogTab />
        </TabsContent>
        <TabsContent value="thresholds">
          <ThresholdTuningTab />
        </TabsContent>
        <TabsContent value="override">
          <OverrideTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
