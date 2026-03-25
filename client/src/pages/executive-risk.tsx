import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  TrendingDown,
  TrendingUp,
  Clock,
  Zap,
  Target,
  BarChart3,
  FileText,
  ChevronRight,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  AlertTriangle,
  CheckCircle2,
  Bot,
  Layers,
  Activity,
  DollarSign,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { SunIcon, ThunderIcon } from "@/components/ui/animated-weather-icons";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

function unwrap(data: unknown): unknown {
  if (data && typeof data === "object" && "data" in data) {
    return (data as Record<string, unknown>).data;
  }
  return data;
}

type TrendDirection = "improving" | "stable" | "degrading";
type RiskSeverity = "critical" | "high" | "medium" | "low" | "info";

interface MttrMetric {
  overall: number;
  bySeverity: Record<RiskSeverity, number>;
  trend: TrendDirection;
  previousPeriod: number;
  changePercent: number;
  unit: string;
}

interface RiskBurndownEntry {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

interface ExploitabilityExposure {
  totalFindings: number;
  exploitable: number;
  exploitablePercent: number;
  weaponized: number;
  weaponizedPercent: number;
  epssAboveThreshold: number;
  epssThreshold: number;
  exposureScore: number;
  trend: TrendDirection;
  previousScore: number;
  changePercent: number;
}

interface RemediationThroughput {
  resolvedThisPeriod: number;
  openedThisPeriod: number;
  netChange: number;
  resolvedPerDay: number;
  averageResolutionDays: number;
  backlogSize: number;
  backlogBySeverity: Record<RiskSeverity, number>;
  trend: TrendDirection;
  previousThroughput: number;
  changePercent: number;
}

interface AutomationSavings {
  totalHoursSaved: number;
  incidentsAutoTriaged: number;
  alertsAutoCorrelated: number;
  playbooksAutoExecuted: number;
  falsePositivesSuppressed: number;
  estimatedCostSavings: number;
  costPerAnalystHour: number;
  automationCoveragePercent: number;
  trend: TrendDirection;
  previousHoursSaved: number;
  changePercent: number;
}

interface ActionMetric {
  id: string;
  name: string;
  description: string;
  category: "action" | "vanity";
  value: number;
  unit: string;
  trend: TrendDirection;
  changePercent: number;
  target: number | null;
  targetMet: boolean;
  sparkline: number[];
}

interface PostureDimension {
  name: string;
  score: number;
  maxScore: number;
  weight: number;
}

interface RiskPostureSnapshot {
  overallScore: number;
  previousScore: number;
  maxScore: number;
  grade: string;
  previousGrade: string;
  dimensions: PostureDimension[];
}

interface BoardFinding {
  id: string;
  title: string;
  severity: RiskSeverity;
  description: string;
  evidence: string[];
  impactArea: string;
  status: "new" | "ongoing" | "resolved";
}

interface BoardRecommendation {
  id: string;
  priority: number;
  title: string;
  description: string;
  expectedImpact: string;
  effort: "low" | "medium" | "high";
  owner: string;
  deadline: string | null;
}

interface BoardSummary {
  id: string;
  orgId: string;
  period: string;
  generatedAt: string;
  generatedBy: string;
  title: string;
  executiveSynopsis: string;
  keyFindings: BoardFinding[];
  riskPosture: RiskPostureSnapshot;
  recommendations: BoardRecommendation[];
  mttr: MttrMetric;
  exploitability: ExploitabilityExposure;
  remediationThroughput: RemediationThroughput;
  automationSavings: AutomationSavings;
}

interface ExecutiveDashboard {
  mttr: MttrMetric;
  riskBurndown: RiskBurndownEntry[];
  exploitability: ExploitabilityExposure;
  remediationThroughput: RemediationThroughput;
  automationSavings: AutomationSavings;
  actionMetrics: ActionMetric[];
  riskPosture: RiskPostureSnapshot;
}

const TABS = [
  { id: "overview", label: "Risk Overview", icon: Shield },
  { id: "metrics", label: "Action Metrics", icon: Target },
  { id: "burndown", label: "Risk Burn-down", icon: TrendingDown },
  { id: "summaries", label: "Board Summaries", icon: FileText },
] as const;

const SEVERITY_COLORS: Record<RiskSeverity, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-slate-400",
};

const SEVERITY_BG: Record<RiskSeverity, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/30",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/30",
};

function TrendBadge({ trend, changePercent }: { trend: TrendDirection; changePercent: number }) {
  if (trend === "improving") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
        <ArrowDownRight className="h-3 w-3" />
        {Math.abs(changePercent).toFixed(1)}%
      </span>
    );
  }
  if (trend === "degrading") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
        <ArrowUpRight className="h-3 w-3" />
        {Math.abs(changePercent).toFixed(1)}%
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-400">
      <Minus className="h-3 w-3" />
      {Math.abs(changePercent).toFixed(1)}%
    </span>
  );
}

function MiniSparkline({ data, color = "stroke-cyan-400" }: { data: number[]; color?: string }) {
  if (!data || data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const w = 80;
  const h = 24;
  const points = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`).join(" ");
  return (
    <svg width={w} height={h} className="inline-block">
      <polyline
        points={points}
        fill="none"
        className={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function GradeRing({ grade, score, maxScore }: { grade: string; score: number; maxScore: number }) {
  const pct = (score / maxScore) * 100;
  const r = 40;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  const gradeColors: Record<string, string> = {
    A: "stroke-emerald-400",
    B: "stroke-cyan-400",
    C: "stroke-yellow-400",
    D: "stroke-orange-400",
    F: "stroke-red-400",
  };
  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="100" height="100" className="-rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" className="stroke-muted/30" strokeWidth="8" />
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          className={gradeColors[grade] || "stroke-cyan-400"}
          strokeWidth="8"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold">{grade}</span>
        <span className="text-xs text-muted-foreground">
          {score}/{maxScore}
        </span>
      </div>
    </div>
  );
}

function OverviewTab({ dashboard }: { dashboard: ExecutiveDashboard }) {
  const { mttr, exploitability, remediationThroughput, automationSavings, riskPosture } = dashboard;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan-400" />
              MTTR (Overall)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end justify-between">
              <div>
                <p className="text-3xl font-bold">{mttr.overall}h</p>
                <TrendBadge trend={mttr.trend} changePercent={mttr.changePercent} />
              </div>
              <div className="text-xs text-muted-foreground text-right">
                <p>Critical: {mttr.bySeverity.critical}h</p>
                <p>High: {mttr.bySeverity.high}h</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
              Exploitable Exposure
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end justify-between">
              <div>
                <p className="text-3xl font-bold">{exploitability.exposureScore}%</p>
                <TrendBadge trend={exploitability.trend} changePercent={exploitability.changePercent} />
              </div>
              <div className="text-xs text-muted-foreground text-right">
                <p>Weaponized: {exploitability.weaponized}</p>
                <p>
                  EPSS &gt; {exploitability.epssThreshold}: {exploitability.epssAboveThreshold}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Activity className="h-4 w-4 text-emerald-400" />
              Remediation Throughput
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end justify-between">
              <div>
                <p className="text-3xl font-bold">{remediationThroughput.resolvedPerDay}/day</p>
                <TrendBadge trend={remediationThroughput.trend} changePercent={remediationThroughput.changePercent} />
              </div>
              <div className="text-xs text-muted-foreground text-right">
                <p>Resolved: {remediationThroughput.resolvedThisPeriod}</p>
                <p>Backlog: {remediationThroughput.backlogSize}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Bot className="h-4 w-4 text-purple-400" />
              Automation Savings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end justify-between">
              <div>
                <p className="text-3xl font-bold">${(automationSavings.estimatedCostSavings / 1000).toFixed(0)}K</p>
                <TrendBadge trend={automationSavings.trend} changePercent={automationSavings.changePercent} />
              </div>
              <div className="text-xs text-muted-foreground text-right">
                <p>{automationSavings.totalHoursSaved} hrs saved</p>
                <p>{automationSavings.automationCoveragePercent}% coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="glass-card lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              Risk Posture
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-center mb-4">
              <GradeRing grade={riskPosture.grade} score={riskPosture.overallScore} maxScore={riskPosture.maxScore} />
            </div>
            <p className="text-xs text-center text-muted-foreground mb-4">
              {riskPosture.previousGrade !== riskPosture.grade
                ? `Improved from ${riskPosture.previousGrade} (${riskPosture.previousScore}) to ${riskPosture.grade} (${riskPosture.overallScore})`
                : `Maintained at ${riskPosture.grade} (${riskPosture.overallScore} vs ${riskPosture.previousScore} prior)`}
            </p>
            <div className="space-y-3">
              {riskPosture.dimensions.map((dim) => (
                <div key={dim.name}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-muted-foreground">{dim.name}</span>
                    <span className="font-medium">
                      {dim.score}/{dim.maxScore}
                    </span>
                  </div>
                  <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
                      style={{ width: `${(dim.score / dim.maxScore) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Zap className="h-4 w-4 text-purple-400" />
              Automation Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                {
                  label: "Incidents Auto-Triaged",
                  value: automationSavings.incidentsAutoTriaged.toLocaleString(),
                  icon: AlertTriangle,
                },
                {
                  label: "Alerts Auto-Correlated",
                  value: automationSavings.alertsAutoCorrelated.toLocaleString(),
                  icon: Layers,
                },
                {
                  label: "Playbooks Executed",
                  value: automationSavings.playbooksAutoExecuted.toLocaleString(),
                  icon: Activity,
                },
                {
                  label: "False Positives Suppressed",
                  value: automationSavings.falsePositivesSuppressed.toLocaleString(),
                  icon: CheckCircle2,
                },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <item.icon className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm text-muted-foreground">{item.label}</span>
                  </div>
                  <span className="text-sm font-medium">{item.value}</span>
                </div>
              ))}
              <div className="pt-3 border-t border-border/50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <DollarSign className="h-4 w-4 text-emerald-400" />
                    <span className="text-sm font-medium">Total Cost Savings</span>
                  </div>
                  <span className="text-sm font-bold text-emerald-400">
                    ${automationSavings.estimatedCostSavings.toLocaleString()}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Based on ${automationSavings.costPerAnalystHour}/hr analyst cost
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingDown className="h-4 w-4 text-cyan-400" />
              Remediation Backlog
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(["critical", "high", "medium", "low", "info"] as RiskSeverity[]).map((sev) => {
                const count = remediationThroughput.backlogBySeverity[sev];
                const maxCount = Math.max(...Object.values(remediationThroughput.backlogBySeverity), 1);
                return (
                  <div key={sev}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className={`capitalize font-medium ${SEVERITY_COLORS[sev]}`}>{sev}</span>
                      <span className="text-muted-foreground">{count} findings</span>
                    </div>
                    <div className="h-2 bg-muted/30 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          sev === "critical"
                            ? "bg-red-500"
                            : sev === "high"
                              ? "bg-orange-500"
                              : sev === "medium"
                                ? "bg-yellow-500"
                                : sev === "low"
                                  ? "bg-blue-500"
                                  : "bg-slate-500"
                        }`}
                        style={{ width: `${(count / maxCount) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
              <div className="pt-3 border-t border-border/50 flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Total backlog</span>
                <span className="text-lg font-bold">{remediationThroughput.backlogSize}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Avg resolution</span>
                <span className="text-sm font-medium">{remediationThroughput.averageResolutionDays} days</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Net change</span>
                <span
                  className={`text-sm font-medium ${remediationThroughput.netChange < 0 ? "text-emerald-400" : "text-red-400"}`}
                >
                  {remediationThroughput.netChange > 0 ? "+" : ""}
                  {remediationThroughput.netChange}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function MetricsTab({ metrics }: { metrics: ActionMetric[] }) {
  const actionMetrics = metrics.filter((m) => m.category === "action");
  const vanityMetrics = metrics.filter((m) => m.category === "vanity");

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1 flex items-center gap-2">
          <Target className="h-5 w-5 text-cyan-400" />
          Action Metrics
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          Metrics that drive security outcomes and require direct action when off-target
        </p>
        {actionMetrics.length === 0 ? (
          <Card className="glass-card">
            <CardContent className="py-12 text-center">
              <Target className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-muted-foreground">No action metrics available</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {actionMetrics.map((metric) => (
              <Card key={metric.id} className="glass-card hover:border-cyan-500/30 transition-colors">
                <CardContent className="pt-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <p className="text-sm font-medium">{metric.name}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{metric.description}</p>
                    </div>
                    <MiniSparkline data={metric.sparkline} />
                  </div>
                  <div className="flex items-end justify-between">
                    <div>
                      <p className="text-2xl font-bold">
                        {metric.value}
                        {metric.unit === "%" ? "%" : ""}
                      </p>
                      {metric.unit !== "%" && <p className="text-xs text-muted-foreground">{metric.unit}</p>}
                    </div>
                    <div className="text-right">
                      <TrendBadge trend={metric.trend} changePercent={metric.changePercent} />
                      {metric.target !== null && (
                        <p className="text-xs mt-1">
                          <span className="text-muted-foreground">
                            Target: {metric.target}
                            {metric.unit === "%" ? "%" : ""}
                          </span>
                          {metric.targetMet ? (
                            <SuccessIcon size={12} color="#22c55e" />
                          ) : (
                            <AlertTriangle className="h-3 w-3 text-yellow-400 inline ml-1" />
                          )}
                        </p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      <div>
        <h3 className="text-lg font-semibold mb-1 flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-slate-400" />
          Operational Metrics
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          Volume and activity metrics for context — not directly actionable
        </p>
        {vanityMetrics.length === 0 ? (
          <Card className="glass-card">
            <CardContent className="py-12 text-center">
              <BarChart3 className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-muted-foreground">No operational metrics available</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {vanityMetrics.map((metric) => (
              <Card key={metric.id} className="glass-card border-dashed">
                <CardContent className="pt-5">
                  <p className="text-xs text-muted-foreground mb-1">{metric.name}</p>
                  <div className="flex items-end justify-between">
                    <p className="text-xl font-bold">
                      {typeof metric.value === "number" && metric.value > 999
                        ? metric.value.toLocaleString()
                        : metric.value}
                      {metric.unit === "%" ? "%" : ""}
                    </p>
                    <MiniSparkline data={metric.sparkline} color="stroke-slate-400" />
                  </div>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-muted-foreground">{metric.unit !== "%" ? metric.unit : ""}</span>
                    <TrendBadge trend={metric.trend} changePercent={metric.changePercent} />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function BurndownTab({ burndown }: { burndown: RiskBurndownEntry[] }) {
  if (!burndown || burndown.length === 0) {
    return (
      <Card className="glass-card">
        <CardContent className="py-12 text-center">
          <TrendingDown className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">No burn-down data available</p>
        </CardContent>
      </Card>
    );
  }

  const latest = burndown[burndown.length - 1];
  const first = burndown[0];
  const totalChange = latest.total - first.total;

  const maxTotal = Math.max(...burndown.map((e) => e.total), 1);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {(["critical", "high", "medium", "low"] as const).map((sev) => (
          <Card key={sev} className="glass-card">
            <CardContent className="pt-4 pb-3 text-center">
              <p className={`text-xs uppercase font-medium ${SEVERITY_COLORS[sev]}`}>{sev}</p>
              <p className="text-2xl font-bold mt-1">{latest[sev]}</p>
              <p className="text-xs text-muted-foreground">
                {latest[sev] - first[sev] > 0 ? "+" : ""}
                {latest[sev] - first[sev]} from start
              </p>
            </CardContent>
          </Card>
        ))}
        <Card className="glass-card col-span-2 md:col-span-1">
          <CardContent className="pt-4 pb-3 text-center">
            <p className="text-xs uppercase font-medium text-muted-foreground">Total</p>
            <p className="text-2xl font-bold mt-1">{latest.total}</p>
            <p
              className={`text-xs ${totalChange < 0 ? "text-emerald-400" : totalChange > 0 ? "text-red-400" : "text-muted-foreground"}`}
            >
              {totalChange > 0 ? "+" : ""}
              {totalChange} net
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="text-sm font-medium">30-Day Risk Burn-down</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {burndown.map((entry, idx) => {
              const barWidth = (entry.total / maxTotal) * 100;
              const critPct = entry.total > 0 ? (entry.critical / entry.total) * barWidth : 0;
              const highPct = entry.total > 0 ? (entry.high / entry.total) * barWidth : 0;
              const medPct = entry.total > 0 ? (entry.medium / entry.total) * barWidth : 0;
              const lowPct = entry.total > 0 ? (entry.low / entry.total) * barWidth : 0;
              const showLabel = idx === 0 || idx === burndown.length - 1 || idx % 7 === 0;
              return (
                <div key={entry.date} className="flex items-center gap-2 group">
                  <span className="text-[10px] text-muted-foreground w-16 text-right font-mono shrink-0">
                    {showLabel ? entry.date.slice(5) : ""}
                  </span>
                  <div className="flex-1 flex h-3 rounded-sm overflow-hidden bg-muted/20">
                    <div className="bg-red-500 transition-all" style={{ width: `${critPct}%` }} />
                    <div className="bg-orange-500 transition-all" style={{ width: `${highPct}%` }} />
                    <div className="bg-yellow-500 transition-all" style={{ width: `${medPct}%` }} />
                    <div className="bg-blue-500 transition-all" style={{ width: `${lowPct}%` }} />
                  </div>
                  <span className="text-[10px] text-muted-foreground w-10 text-right font-mono shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    {entry.total}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-4 mt-4 text-xs text-muted-foreground justify-center">
            <span className="flex items-center gap-1">
              <span className="w-3 h-2 rounded-sm bg-red-500 inline-block" /> Critical
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-2 rounded-sm bg-orange-500 inline-block" /> High
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-2 rounded-sm bg-yellow-500 inline-block" /> Medium
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-2 rounded-sm bg-blue-500 inline-block" /> Low
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function SummariesTab({
  orgSummaries,
  onGenerate,
  generating,
}: {
  orgSummaries: BoardSummary[];
  onGenerate: (period: string) => void;
  generating: boolean;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Board-Ready Summaries</h3>
          <p className="text-sm text-muted-foreground">Periodic security risk reports with drill-down evidence</p>
        </div>
        <div className="flex gap-2">
          {(["weekly", "monthly", "quarterly"] as const).map((period) => (
            <Button
              key={period}
              variant="outline"
              size="sm"
              onClick={() => onGenerate(period)}
              disabled={generating}
              className="capitalize hover:bg-cyan-500/10 hover:border-cyan-500/30 active:scale-95 transition-all"
            >
              {generating ? "Generating..." : `Generate ${period}`}
            </Button>
          ))}
        </div>
      </div>

      {orgSummaries.length === 0 ? (
        <Card className="glass-card">
          <CardContent className="py-12 text-center">
            <FileText className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">No board summaries generated yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Click a generate button above to create your first report
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {orgSummaries.map((summary) => {
            const isExpanded = expandedId === summary.id;
            return (
              <Card key={summary.id} className="glass-card">
                <CardContent className="pt-5">
                  <button
                    onClick={() => setExpandedId(isExpanded ? null : summary.id)}
                    className="w-full text-left focus:outline-none focus:ring-2 focus:ring-cyan-500/50 rounded-md"
                    aria-expanded={isExpanded}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className="capitalize">
                          {summary.period}
                        </Badge>
                        <span className="font-medium text-sm">{summary.title}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground">
                          {new Date(summary.generatedAt).toLocaleDateString()}
                        </span>
                        <ChevronRight
                          className={`h-4 w-4 text-muted-foreground transition-transform ${isExpanded ? "rotate-90" : ""}`}
                        />
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground mt-2 line-clamp-2">{summary.executiveSynopsis}</p>
                  </button>

                  {isExpanded && (
                    <div className="mt-6 space-y-6 border-t border-border/50 pt-6">
                      <div>
                        <h4 className="text-sm font-semibold mb-2">Executive Synopsis</h4>
                        <p className="text-sm text-muted-foreground leading-relaxed">{summary.executiveSynopsis}</p>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="rounded-md border border-border/50 p-3 text-center">
                          <p className="text-xs text-muted-foreground">MTTR</p>
                          <p className="text-lg font-bold">{summary.mttr.overall}h</p>
                          <TrendBadge trend={summary.mttr.trend} changePercent={summary.mttr.changePercent} />
                        </div>
                        <div className="rounded-md border border-border/50 p-3 text-center">
                          <p className="text-xs text-muted-foreground">Exposure</p>
                          <p className="text-lg font-bold">{summary.exploitability.exposureScore}%</p>
                          <TrendBadge
                            trend={summary.exploitability.trend}
                            changePercent={summary.exploitability.changePercent}
                          />
                        </div>
                        <div className="rounded-md border border-border/50 p-3 text-center">
                          <p className="text-xs text-muted-foreground">Resolved</p>
                          <p className="text-lg font-bold">{summary.remediationThroughput.resolvedThisPeriod}</p>
                          <TrendBadge
                            trend={summary.remediationThroughput.trend}
                            changePercent={summary.remediationThroughput.changePercent}
                          />
                        </div>
                        <div className="rounded-md border border-border/50 p-3 text-center">
                          <p className="text-xs text-muted-foreground">Savings</p>
                          <p className="text-lg font-bold">
                            ${(summary.automationSavings.estimatedCostSavings / 1000).toFixed(0)}K
                          </p>
                          <TrendBadge
                            trend={summary.automationSavings.trend}
                            changePercent={summary.automationSavings.changePercent}
                          />
                        </div>
                      </div>

                      {summary.keyFindings.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-3">Key Findings</h4>
                          <div className="space-y-3">
                            {summary.keyFindings.map((finding) => (
                              <div key={finding.id} className="rounded-md border border-border/50 p-3">
                                <div className="flex items-start gap-3">
                                  <Badge className={`${SEVERITY_BG[finding.severity]} shrink-0 capitalize`}>
                                    {finding.severity}
                                  </Badge>
                                  <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium">{finding.title}</p>
                                    <p className="text-xs text-muted-foreground mt-1">{finding.description}</p>
                                    <div className="flex flex-wrap gap-1 mt-2">
                                      {finding.evidence.map((e) => (
                                        <Badge key={e} variant="outline" className="text-[10px]">
                                          {e}
                                        </Badge>
                                      ))}
                                    </div>
                                    <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                                      <span>Impact: {finding.impactArea}</span>
                                      <Badge
                                        variant="outline"
                                        className={`capitalize text-[10px] ${
                                          finding.status === "resolved"
                                            ? "text-emerald-400 border-emerald-500/30"
                                            : finding.status === "new"
                                              ? "text-cyan-400 border-cyan-500/30"
                                              : "text-yellow-400 border-yellow-500/30"
                                        }`}
                                      >
                                        {finding.status}
                                      </Badge>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {summary.recommendations.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-3">Recommendations</h4>
                          <div className="space-y-3">
                            {summary.recommendations.map((rec) => (
                              <div key={rec.id} className="rounded-md border border-border/50 p-3">
                                <div className="flex items-start gap-3">
                                  <span className="flex items-center justify-center h-6 w-6 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold shrink-0">
                                    {rec.priority}
                                  </span>
                                  <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium">{rec.title}</p>
                                    <p className="text-xs text-muted-foreground mt-1">{rec.description}</p>
                                    <div className="flex flex-wrap items-center gap-3 mt-2 text-xs text-muted-foreground">
                                      <span>Impact: {rec.expectedImpact}</span>
                                    </div>
                                    <div className="flex items-center gap-3 mt-2">
                                      <Badge
                                        variant="outline"
                                        className={`capitalize text-[10px] ${
                                          rec.effort === "low"
                                            ? "text-emerald-400 border-emerald-500/30"
                                            : rec.effort === "medium"
                                              ? "text-yellow-400 border-yellow-500/30"
                                              : "text-red-400 border-red-500/30"
                                        }`}
                                      >
                                        {rec.effort} effort
                                      </Badge>
                                      <span className="text-xs text-muted-foreground">Owner: {rec.owner}</span>
                                      {rec.deadline && (
                                        <span className="text-xs text-muted-foreground">Due: {rec.deadline}</span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div>
                        <h4 className="text-sm font-semibold mb-3">Risk Posture</h4>
                        <div className="flex items-center gap-6">
                          <GradeRing
                            grade={summary.riskPosture.grade}
                            score={summary.riskPosture.overallScore}
                            maxScore={summary.riskPosture.maxScore}
                          />
                          <div className="flex-1 space-y-2">
                            {summary.riskPosture.dimensions.map((dim) => (
                              <div key={dim.name} className="flex items-center gap-2">
                                <span className="text-xs text-muted-foreground w-40 shrink-0">{dim.name}</span>
                                <div className="flex-1 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                                  <div
                                    className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                                    style={{ width: `${(dim.score / dim.maxScore) * 100}%` }}
                                  />
                                </div>
                                <span className="text-xs font-medium w-8 text-right">{dim.score}</span>
                              </div>
                            ))}
                          </div>
                        </div>
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

export default function ExecutiveRiskPage() {
  const [activeTab, setActiveTab] = useState<(typeof TABS)[number]["id"]>("overview");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: dashboardRaw, isLoading: dashLoading } = useQuery({
    queryKey: ["/api/executive-risk/dashboard"],
    queryFn: () => apiRequest("GET", "/api/executive-risk/dashboard").then((r) => r.json()),
  });

  const { data: summariesRaw, isLoading: summLoading } = useQuery({
    queryKey: ["/api/executive-risk/summaries"],
    queryFn: () => apiRequest("GET", "/api/executive-risk/summaries").then((r) => r.json()),
  });

  const generateMutation = useMutation({
    mutationFn: (period: string) => apiRequest("POST", "/api/executive-risk/summaries/generate", { period }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/executive-risk/summaries"] });
      toast({ title: "Board summary generated", description: "New report is available in the summaries tab" });
    },
    onError: () => {
      toast({ title: "Generation failed", description: "Could not generate board summary", variant: "destructive" });
    },
  });

  const dashboard = unwrap(dashboardRaw) as ExecutiveDashboard | undefined;
  const summaries = (unwrap(summariesRaw) as BoardSummary[] | undefined) || [];

  if (dashLoading) {
    return (
      <div className="p-6 space-y-6" role="status" aria-label="Loading executive risk dashboard">
        <Skeleton className="h-8 w-72" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
        <Skeleton className="h-64 w-full" />
        <span className="sr-only">Loading executive risk data...</span>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-cyan-400" />
            Executive Risk & Outcomes
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Business-facing security metrics with board-ready summaries and drill-down evidence
          </p>
        </div>
      </div>

      <div className="flex gap-1 border-b border-border/50 overflow-x-auto" role="tablist">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-all whitespace-nowrap hover:text-foreground active:scale-95 ${
              activeTab === tab.id
                ? "border-cyan-400 text-foreground"
                : "border-transparent text-muted-foreground hover:border-muted-foreground/30"
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && dashboard && <OverviewTab dashboard={dashboard} />}
      {activeTab === "metrics" && dashboard && <MetricsTab metrics={dashboard.actionMetrics} />}
      {activeTab === "burndown" && dashboard && <BurndownTab burndown={dashboard.riskBurndown} />}
      {activeTab === "summaries" && (
        <SummariesTab
          orgSummaries={summaries}
          onGenerate={(period) => generateMutation.mutate(period)}
          generating={generateMutation.isPending}
        />
      )}

      {!dashboard && !dashLoading && (
        <Card className="glass-card">
          <CardContent className="py-12 text-center">
            <Shield className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">No executive risk data available</p>
            <p className="text-xs text-muted-foreground mt-1">Data will appear once security findings are processed</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
