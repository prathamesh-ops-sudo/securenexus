import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Bug,
  Play,
  RefreshCw,
  Calendar,
  Clock,
  Target,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronRight,
  Search,
  Layers,
  Bot,
  Globe,
  Key,
  Zap,
  Terminal,
  FileWarning,
  Fingerprint,
  Cloud,
  Crosshair,
  BarChart3,
  ListChecks,
  Timer,
  ArrowRight,
  PlayCircle,
  Pause,
  Trash2,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

interface AttackTestCase {
  id: string;
  name: string;
  description: string;
  domain: string;
  category: string;
  phase: string;
  severity: string;
  version: number;
  controlIds: string[];
  policyOwner: string;
  payload: string;
  expectedBehavior: string;
  tags: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface TestExecution {
  id: string;
  orgId: string;
  testCaseId: string;
  testCaseName: string;
  domain: string;
  category: string;
  phase: string;
  status: string;
  trigger: string;
  verdict: string;
  durationMs: number;
  output: string;
  remediationQueued: boolean;
  guardrailTuned: boolean;
  executedBy: string;
  executedAt: string;
  retestOf: string | null;
}

interface TestSchedule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  frequency: string;
  domains: string[];
  categories: string[];
  phase: string;
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string;
  testCaseIds: string[];
  createdAt: string;
  updatedAt: string;
}

interface RemediationItem {
  id: string;
  orgId: string;
  executionId: string;
  testCaseId: string;
  testCaseName: string;
  category: string;
  severity: string;
  controlIds: string[];
  policyOwner: string;
  status: string;
  assignedTo: string | null;
  notes: string;
  guardrailPolicyId: string | null;
  createdAt: string;
  resolvedAt: string | null;
}

interface AdversarialStats {
  totalTestCases: number;
  enabledTestCases: number;
  totalExecutions: number;
  passedCount: number;
  failedCount: number;
  errorCount: number;
  bypassRate: number;
  openRemediations: number;
  scheduledProbes: number;
  lastRunAt: string | null;
  byDomain: Record<string, { total: number; passed: number; failed: number }>;
  byCategory: Record<string, { total: number; passed: number; failed: number }>;
  coveragePercent: number;
}

const DOMAIN_CONFIG: Record<string, { label: string; icon: typeof Shield; color: string }> = {
  application: { label: "Application", icon: Globe, color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  identity: { label: "Identity", icon: Fingerprint, color: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  cloud: { label: "Cloud", icon: Cloud, color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
  ai_agent: { label: "AI Agent", icon: Bot, color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
};

const CATEGORY_CONFIG: Record<string, { label: string; icon: typeof Shield }> = {
  prompt_injection: { label: "Prompt Injection", icon: Bot },
  evasion: { label: "Evasion", icon: ShieldAlert },
  tool_misuse: { label: "Tool Misuse", icon: Terminal },
  privilege_escalation: { label: "Privilege Escalation", icon: Key },
  secret_leakage: { label: "Secret Leakage", icon: FileWarning },
  xss: { label: "XSS", icon: Zap },
  sqli: { label: "SQL Injection", icon: Target },
  ssrf: { label: "SSRF", icon: Globe },
  csrf: { label: "CSRF", icon: Crosshair },
  auth_bypass: { label: "Auth Bypass", icon: Fingerprint },
};

const SEVERITY_CONFIG: Record<string, { label: string; color: string }> = {
  info: { label: "Info", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
  low: { label: "Low", color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  medium: { label: "Medium", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  high: { label: "High", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  critical: { label: "Critical", color: "bg-red-500/20 text-red-400 border-red-500/30" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  passed: { label: "Passed", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
  failed: { label: "Failed", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: XCircle },
  running: { label: "Running", color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Play },
  pending: { label: "Pending", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30", icon: Clock },
  error: { label: "Error", color: "bg-orange-500/20 text-orange-400 border-orange-500/30", icon: AlertTriangle },
  skipped: { label: "Skipped", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30", icon: Pause },
};

const VERDICT_CONFIG: Record<string, { label: string; color: string }> = {
  blocked: { label: "Blocked", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  detected: { label: "Detected", color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
  bypassed: { label: "Bypassed", color: "bg-red-500/20 text-red-400 border-red-500/30" },
  inconclusive: { label: "Inconclusive", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
};

const PHASE_CONFIG: Record<string, { label: string; color: string }> = {
  pre_production: { label: "Pre-Production", color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  production_safe: { label: "Production Safe", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  post_fix: { label: "Post-Fix", color: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
};

const REMEDIATION_STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  open: { label: "Open", color: "bg-red-500/20 text-red-400 border-red-500/30" },
  in_progress: { label: "In Progress", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  resolved: { label: "Resolved", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  wont_fix: { label: "Won't Fix", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
};

const FREQUENCY_CONFIG: Record<string, string> = {
  hourly: "Every hour",
  daily: "Daily",
  weekly: "Weekly",
  monthly: "Monthly",
  on_deploy: "On Deploy",
};

type TabId = "library" | "executions" | "schedules" | "remediations";

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: typeof Shield;
  accent?: string;
}) {
  return (
    <Card className="glass-card border-white/5">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={`p-2 rounded-lg ${accent || "bg-cyan-500/10"}`}>
          <Icon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
        </div>
        <div>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
          <p className="text-xl font-bold">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function DomainBreakdown({
  byDomain,
}: {
  byDomain: Record<string, { total: number; passed: number; failed: number }>;
}) {
  const entries = Object.entries(byDomain);
  if (entries.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Coverage by Domain
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-4">
          <p className="text-xs text-muted-foreground">No domain data available yet. Run some tests to see coverage.</p>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          Coverage by Domain
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4 space-y-3">
        {entries.map(([domain, data]) => {
          const conf = DOMAIN_CONFIG[domain] || DOMAIN_CONFIG.application;
          const DomainIcon = conf.icon;
          const passRate = data.total > 0 ? Math.round((data.passed / data.total) * 100) : 0;
          return (
            <div key={domain} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <DomainIcon className="h-3 w-3 text-cyan-400" aria-hidden="true" />
                  <span>{conf.label}</span>
                </div>
                <span className="text-muted-foreground">
                  {data.passed}/{data.total} passed ({passRate}%)
                </span>
              </div>
              <div
                className="h-1.5 bg-white/5 rounded-full overflow-hidden"
                role="progressbar"
                aria-valuenow={passRate}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={`${conf.label} pass rate`}
              >
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all duration-500"
                  style={{ width: `${passRate}%` }}
                />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function CategoryBreakdown({
  byCategory,
}: {
  byCategory: Record<string, { total: number; passed: number; failed: number }>;
}) {
  const entries = Object.entries(byCategory).sort((a, b) => b[1].failed - a[1].failed);
  if (entries.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Results by Category
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-4">
          <p className="text-xs text-muted-foreground">
            No category data available yet. Run some tests to see results.
          </p>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          Results by Category
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4 space-y-2">
        {entries.slice(0, 8).map(([category, data]) => {
          const conf = CATEGORY_CONFIG[category] || { label: category, icon: Bug };
          const CatIcon = conf.icon;
          return (
            <div
              key={category}
              className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0"
            >
              <div className="flex items-center gap-1.5">
                <CatIcon className="h-3 w-3 text-cyan-400" aria-hidden="true" />
                <span>{conf.label}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-emerald-400">{data.passed}P</span>
                <span className="text-red-400">{data.failed}F</span>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function TestCaseCard({
  tc,
  isExpanded,
  onToggle,
  onRun,
  isRunning,
}: {
  tc: AttackTestCase;
  isExpanded: boolean;
  onToggle: () => void;
  onRun: () => void;
  isRunning: boolean;
}) {
  const domainConf = DOMAIN_CONFIG[tc.domain] || DOMAIN_CONFIG.application;
  const DomainIcon = domainConf.icon;
  const catConf = CATEGORY_CONFIG[tc.category] || { label: tc.category, icon: Bug };
  const CatIcon = catConf.icon;
  const sevConf = SEVERITY_CONFIG[tc.severity] || SEVERITY_CONFIG.medium;
  const phaseConf = PHASE_CONFIG[tc.phase] || PHASE_CONFIG.pre_production;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={onToggle}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <CatIcon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{tc.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                  {sevConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${domainConf.color}`}>
                  <DomainIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {domainConf.label}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{tc.description}</p>
              <div className="flex items-center gap-2 mt-2 flex-wrap">
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${phaseConf.color}`}>
                  {phaseConf.label}
                </Badge>
                <span className="text-[10px] text-muted-foreground">v{tc.version}</span>
                <span className="text-[10px] text-muted-foreground">Owner: {tc.policyOwner}</span>
                {tc.tags.slice(0, 3).map((tag) => (
                  <Badge
                    key={tag}
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/5 text-cyan-400/70 border-cyan-500/10"
                  >
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                onRun();
              }}
              disabled={isRunning || !tc.enabled}
              aria-label={`Run test: ${tc.name}`}
            >
              {isRunning ? <RefreshCw className="h-3 w-3 animate-spin" /> : <PlayCircle className="h-3 w-3" />}
              <span className="ml-1">{isRunning ? "Running" : "Run"}</span>
            </Button>
            {isExpanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </button>
      {isExpanded && (
        <div className="px-4 pb-4 border-t border-white/5 pt-3 space-y-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Attack Payload</p>
            <pre className="text-xs font-mono bg-black/30 rounded px-3 py-2 text-red-300/80 overflow-x-auto whitespace-pre-wrap">
              {tc.payload}
            </pre>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Expected Behavior</p>
            <p className="text-xs text-emerald-300/80 bg-black/20 rounded px-3 py-2">{tc.expectedBehavior}</p>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Mapped Controls</p>
            <div className="flex flex-wrap gap-1.5">
              {tc.controlIds.map((ctrl) => (
                <Badge key={ctrl} variant="outline" className="text-[10px] px-2 py-0.5 bg-white/5 border-white/10">
                  {ctrl}
                </Badge>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
            <span>Created: {new Date(tc.createdAt).toLocaleDateString()}</span>
            <span>Updated: {new Date(tc.updatedAt).toLocaleDateString()}</span>
            <span>Status: {tc.enabled ? "Enabled" : "Disabled"}</span>
          </div>
        </div>
      )}
    </Card>
  );
}

function ExecutionRow({ execution, onRetest }: { execution: TestExecution; onRetest?: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const statusConf = STATUS_CONFIG[execution.status] || STATUS_CONFIG.pending;
  const StatusIcon = statusConf.icon;
  const verdictConf = VERDICT_CONFIG[execution.verdict] || VERDICT_CONFIG.inconclusive;
  const domainConf = DOMAIN_CONFIG[execution.domain] || DOMAIN_CONFIG.application;
  const DomainIcon = domainConf.icon;

  return (
    <div className="glass-card border border-white/5 rounded-lg hover:border-cyan-500/15 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-3 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-center gap-3">
          <StatusIcon
            className={`h-4 w-4 shrink-0 ${execution.status === "passed" ? "text-emerald-400" : execution.status === "failed" ? "text-red-400" : "text-yellow-400"}`}
            aria-hidden="true"
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-medium truncate">{execution.testCaseName}</span>
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${statusConf.color}`}>
                {statusConf.label}
              </Badge>
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                {verdictConf.label}
              </Badge>
            </div>
            <div className="flex items-center gap-2 mt-0.5 text-[10px] text-muted-foreground flex-wrap">
              <DomainIcon className="h-3 w-3" aria-hidden="true" />
              <span>{domainConf.label}</span>
              <span>|</span>
              <span>{execution.category.replace(/_/g, " ")}</span>
              <span>|</span>
              <Timer className="h-3 w-3" aria-hidden="true" />
              <span>{execution.durationMs}ms</span>
              <span>|</span>
              <span>{execution.trigger.replace(/_/g, " ")}</span>
              {execution.retestOf && (
                <>
                  <span>|</span>
                  <RefreshCw className="h-3 w-3 text-purple-400" aria-hidden="true" />
                  <span className="text-purple-400">Retest</span>
                </>
              )}
            </div>
          </div>
          <span className="text-[10px] text-muted-foreground shrink-0">
            {new Date(execution.executedAt).toLocaleString()}
          </span>
          {expanded ? (
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
          )}
        </div>
      </button>
      {expanded && (
        <div className="px-3 pb-3 border-t border-white/5 pt-2 space-y-2">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Output</p>
            <pre className="text-xs font-mono bg-black/30 rounded px-2 py-1.5 text-cyan-300/80 whitespace-pre-wrap">
              {execution.output}
            </pre>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground flex-wrap">
            <span>Phase: {(PHASE_CONFIG[execution.phase] || { label: execution.phase }).label}</span>
            <span>Executed by: {execution.executedBy}</span>
            {execution.remediationQueued && (
              <Badge
                variant="outline"
                className="text-[9px] px-1.5 py-0 h-4 bg-red-500/10 text-red-400 border-red-500/20"
              >
                Remediation Queued
              </Badge>
            )}
            {execution.guardrailTuned && (
              <Badge
                variant="outline"
                className="text-[9px] px-1.5 py-0 h-4 bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
              >
                Guardrail Tuned
              </Badge>
            )}
          </div>
          {execution.status === "failed" && onRetest && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-[10px] hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
              onClick={onRetest}
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              Retest After Fix
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function ScheduleCard({
  schedule,
  onToggle,
  onDelete,
}: {
  schedule: TestSchedule;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className={`p-2 rounded-lg ${schedule.enabled ? "bg-emerald-500/10" : "bg-zinc-500/10"}`}>
              <Calendar
                className={`h-4 w-4 ${schedule.enabled ? "text-emerald-400" : "text-zinc-400"}`}
                aria-hidden="true"
              />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{schedule.name}</h3>
                <Badge
                  variant="outline"
                  className={`text-[9px] px-1.5 py-0 h-4 ${schedule.enabled ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-zinc-500/20 text-zinc-400 border-zinc-500/30"}`}
                >
                  {schedule.enabled ? "Active" : "Paused"}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                >
                  {FREQUENCY_CONFIG[schedule.frequency] || schedule.frequency}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{schedule.description}</p>
              <div className="flex items-center gap-2 mt-1.5 text-[10px] text-muted-foreground">
                <span>{schedule.testCaseIds.length} test cases</span>
                <span>|</span>
                <span>Next: {new Date(schedule.nextRunAt).toLocaleDateString()}</span>
                {schedule.lastRunAt && (
                  <>
                    <span>|</span>
                    <span>Last: {new Date(schedule.lastRunAt).toLocaleDateString()}</span>
                  </>
                )}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0 mt-1">
            <Button
              size="sm"
              variant="ghost"
              className="h-7 w-7 p-0 hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
              aria-label={schedule.enabled ? "Pause schedule" : "Enable schedule"}
            >
              {schedule.enabled ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 w-7 p-0 hover:bg-red-500/10 hover:text-red-400 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                onDelete();
              }}
              aria-label={`Delete schedule: ${schedule.name}`}
            >
              <Trash2 className="h-3 w-3" />
            </Button>
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 border-t border-white/5 pt-3 space-y-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Domains</p>
            <div className="flex flex-wrap gap-1.5">
              {schedule.domains.map((d) => {
                const conf = DOMAIN_CONFIG[d] || DOMAIN_CONFIG.application;
                return (
                  <Badge key={d} variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${conf.color}`}>
                    {conf.label}
                  </Badge>
                );
              })}
            </div>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Categories</p>
            <div className="flex flex-wrap gap-1.5">
              {schedule.categories.map((c) => {
                const conf = CATEGORY_CONFIG[c] || { label: c, icon: Bug };
                return (
                  <Badge key={c} variant="outline" className="text-[9px] px-1.5 py-0 h-4 bg-white/5 border-white/10">
                    {conf.label}
                  </Badge>
                );
              })}
            </div>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
              Test Cases ({schedule.testCaseIds.length})
            </p>
            <div className="flex flex-wrap gap-1.5">
              {schedule.testCaseIds.map((id) => (
                <Badge
                  key={id}
                  variant="outline"
                  className="text-[10px] px-2 py-0.5 bg-white/5 border-white/10 font-mono"
                >
                  {id}
                </Badge>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
            <span>Phase: {(PHASE_CONFIG[schedule.phase] || { label: schedule.phase }).label}</span>
            <span>Created: {new Date(schedule.createdAt).toLocaleDateString()}</span>
          </div>
        </div>
      )}
    </Card>
  );
}

function RemediationCard({
  item,
  onRetest,
  isRetesting,
  onUpdateStatus,
}: {
  item: RemediationItem;
  onRetest: () => void;
  isRetesting: boolean;
  onUpdateStatus: (status: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const statusConf = REMEDIATION_STATUS_CONFIG[item.status] || REMEDIATION_STATUS_CONFIG.open;
  const sevConf = SEVERITY_CONFIG[item.severity] || SEVERITY_CONFIG.medium;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div
              className={`p-2 rounded-lg ${item.status === "open" ? "bg-red-500/10" : item.status === "resolved" ? "bg-emerald-500/10" : "bg-yellow-500/10"}`}
            >
              <AlertTriangle
                className={`h-4 w-4 ${item.status === "open" ? "text-red-400" : item.status === "resolved" ? "text-emerald-400" : "text-yellow-400"}`}
                aria-hidden="true"
              />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{item.testCaseName}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${statusConf.color}`}>
                  {statusConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                  {sevConf.label}
                </Badge>
              </div>
              <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground flex-wrap">
                <span>{item.category.replace(/_/g, " ")}</span>
                <span>|</span>
                <span>Owner: {item.policyOwner}</span>
                {item.assignedTo && (
                  <>
                    <span>|</span>
                    <span>Assigned: {item.assignedTo}</span>
                  </>
                )}
              </div>
            </div>
          </div>
          <div className="shrink-0 mt-1">
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 border-t border-white/5 pt-3 space-y-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Control IDs</p>
            <div className="flex flex-wrap gap-1.5">
              {item.controlIds.map((ctrl) => (
                <Badge key={ctrl} variant="outline" className="text-[10px] px-2 py-0.5 bg-white/5 border-white/10">
                  {ctrl}
                </Badge>
              ))}
            </div>
          </div>
          {item.notes && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Notes</p>
              <p className="text-xs text-cyan-300/80 bg-black/20 rounded px-3 py-2">{item.notes}</p>
            </div>
          )}
          <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
            <span>Created: {new Date(item.createdAt).toLocaleDateString()}</span>
            {item.resolvedAt && <span>Resolved: {new Date(item.resolvedAt).toLocaleDateString()}</span>}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {item.status !== "resolved" && (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-[10px] hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
                onClick={onRetest}
                disabled={isRetesting}
              >
                {isRetesting ? (
                  <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                ) : (
                  <RefreshCw className="h-3 w-3 mr-1" />
                )}
                Retest
              </Button>
            )}
            {item.status === "open" && (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-[10px] hover:bg-yellow-500/10 hover:text-yellow-400 hover:border-yellow-500/30 transition-colors"
                onClick={() => onUpdateStatus("in_progress")}
              >
                <ArrowRight className="h-3 w-3 mr-1" />
                Start
              </Button>
            )}
            {item.status === "in_progress" && (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-[10px] hover:bg-emerald-500/10 hover:text-emerald-400 hover:border-emerald-500/30 transition-colors"
                onClick={() => onUpdateStatus("resolved")}
              >
                <CheckCircle2 className="h-3 w-3 text-green-500" />
                Resolve
              </Button>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

export default function AdversarialTestingPage() {
  const [activeTab, setActiveTab] = useState<TabId>("library");
  const [searchQuery, setSearchQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [expandedTests, setExpandedTests] = useState<Set<string>>(new Set());
  const [runningTests, setRunningTests] = useState<Set<string>>(new Set());
  const [retestingRemediations, setRetestingRemediations] = useState<Set<string>>(new Set());
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: stats, isLoading: statsLoading } = useQuery<AdversarialStats>({
    queryKey: ["/api/adversarial-testing/stats"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/adversarial-testing/stats");
      return res.json();
    },
  });

  const { data: library, isLoading: libraryLoading } = useQuery<AttackTestCase[]>({
    queryKey: ["/api/adversarial-testing/library"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/adversarial-testing/library");
      return res.json();
    },
  });

  const { data: executions, isLoading: executionsLoading } = useQuery<TestExecution[]>({
    queryKey: ["/api/adversarial-testing/executions"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/adversarial-testing/executions");
      return res.json();
    },
  });

  const { data: schedules, isLoading: schedulesLoading } = useQuery<TestSchedule[]>({
    queryKey: ["/api/adversarial-testing/schedules"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/adversarial-testing/schedules");
      return res.json();
    },
  });

  const { data: remediations, isLoading: remediationsLoading } = useQuery<RemediationItem[]>({
    queryKey: ["/api/adversarial-testing/remediations"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/adversarial-testing/remediations");
      return res.json();
    },
  });

  const runTestMutation = useMutation({
    mutationFn: async (testCaseId: string) => {
      const res = await apiRequest("POST", "/api/adversarial-testing/run", {
        testCaseId,
        trigger: "manual",
      });
      return res.json();
    },
    onSuccess: (data: TestExecution) => {
      toast({
        title: data.status === "passed" ? "Test Passed" : "Test Failed",
        description: `${data.testCaseName} — ${data.verdict}`,
        variant: data.status === "passed" ? "default" : "destructive",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/executions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/remediations"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to execute test", variant: "destructive" });
    },
  });

  const retestMutation = useMutation({
    mutationFn: async (remediationId: string) => {
      const res = await apiRequest("POST", `/api/adversarial-testing/remediations/${remediationId}/retest`);
      return res.json();
    },
    onSuccess: (data: TestExecution) => {
      toast({
        title: data.status === "passed" ? "Retest Passed" : "Retest Failed",
        description: `${data.testCaseName} — ${data.verdict}`,
        variant: data.status === "passed" ? "default" : "destructive",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/executions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/remediations"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Retest failed", variant: "destructive" });
    },
  });

  const toggleScheduleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/adversarial-testing/schedules/${id}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/schedules"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/stats"] });
    },
  });

  const deleteScheduleMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("DELETE", `/api/adversarial-testing/schedules/${id}`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Schedule Deleted", description: "Probe schedule has been removed" });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/schedules"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/stats"] });
    },
  });

  const updateRemediationMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const res = await apiRequest("PATCH", `/api/adversarial-testing/remediations/${id}`, { status });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/remediations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/stats"] });
    },
  });

  const handleRunTest = async (testCaseId: string) => {
    setRunningTests((prev) => new Set(prev).add(testCaseId));
    try {
      await runTestMutation.mutateAsync(testCaseId);
    } finally {
      setRunningTests((prev) => {
        const next = new Set(prev);
        next.delete(testCaseId);
        return next;
      });
    }
  };

  const handleRetest = async (remediationId: string) => {
    setRetestingRemediations((prev) => new Set(prev).add(remediationId));
    try {
      await retestMutation.mutateAsync(remediationId);
    } finally {
      setRetestingRemediations((prev) => {
        const next = new Set(prev);
        next.delete(remediationId);
        return next;
      });
    }
  };

  const toggleTestExpand = (id: string) => {
    setExpandedTests((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredLibrary = (library || []).filter((tc) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (
        !tc.name.toLowerCase().includes(q) &&
        !tc.description.toLowerCase().includes(q) &&
        !tc.category.toLowerCase().includes(q) &&
        !tc.tags.some((t) => t.toLowerCase().includes(q))
      )
        return false;
    }
    if (domainFilter && tc.domain !== domainFilter) return false;
    if (categoryFilter && tc.category !== categoryFilter) return false;
    return true;
  });

  const filteredExecutions = (executions || []).filter((e) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!e.testCaseName.toLowerCase().includes(q) && !e.category.toLowerCase().includes(q)) return false;
    }
    if (domainFilter && e.domain !== domainFilter) return false;
    if (categoryFilter && e.category !== categoryFilter) return false;
    return true;
  });

  const filteredRemediations = (remediations || []).filter((r) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!r.testCaseName.toLowerCase().includes(q) && !r.category.toLowerCase().includes(q)) return false;
    }
    if (categoryFilter && r.category !== categoryFilter) return false;
    return true;
  });

  const tabs: { id: TabId; label: string; icon: typeof Shield; count?: number }[] = [
    { id: "library", label: "Attack Library", icon: Bug, count: library?.length },
    { id: "executions", label: "Executions", icon: Play, count: executions?.length },
    { id: "schedules", label: "Schedules", icon: Calendar, count: schedules?.length },
    {
      id: "remediations",
      label: "Remediations",
      icon: ListChecks,
      count: remediations?.filter((r) => r.status === "open" || r.status === "in_progress").length,
    },
  ];

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-red-400" aria-hidden="true" />
            Adversarial Testing
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Continuous testing across application, identity, cloud, and AI/agent behavior
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="h-8 text-xs hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/stats"] });
            queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/library"] });
            queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/executions"] });
            queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/schedules"] });
            queryClient.invalidateQueries({ queryKey: ["/api/adversarial-testing/remediations"] });
          }}
        >
          <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
          Refresh
        </Button>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard label="Test Cases" value={stats.totalTestCases} icon={Bug} accent="bg-cyan-500/10" />
          <StatCard
            label="Pass Rate"
            value={
              stats.totalExecutions > 0 ? `${Math.round((stats.passedCount / stats.totalExecutions) * 100)}%` : "N/A"
            }
            icon={ShieldCheck}
            accent="bg-emerald-500/10"
          />
          <StatCard label="Bypass Rate" value={`${stats.bypassRate}%`} icon={ShieldAlert} accent="bg-red-500/10" />
          <StatCard label="Open Fixes" value={stats.openRemediations} icon={AlertTriangle} accent="bg-orange-500/10" />
          <StatCard label="Scheduled" value={stats.scheduledProbes} icon={Calendar} accent="bg-purple-500/10" />
          <StatCard label="Coverage" value={`${stats.coveragePercent}%`} icon={Target} accent="bg-blue-500/10" />
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="glass-card border-white/5">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground">No stats available</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <DomainBreakdown byDomain={stats?.byDomain || {}} />
        <CategoryBreakdown byCategory={stats?.byCategory || {}} />
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder="Search tests, categories, tags..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 h-9 bg-black/20 border-white/10 text-sm focus:border-cyan-500/30"
            aria-label="Search adversarial tests"
          />
        </div>
        <select
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          className="h-9 px-3 rounded-md border border-white/10 bg-black/20 text-sm focus:border-cyan-500/30 focus:outline-none"
          aria-label="Filter by domain"
        >
          <option value="">All Domains</option>
          {Object.entries(DOMAIN_CONFIG).map(([key, conf]) => (
            <option key={key} value={key}>
              {conf.label}
            </option>
          ))}
        </select>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="h-9 px-3 rounded-md border border-white/10 bg-black/20 text-sm focus:border-cyan-500/30 focus:outline-none"
          aria-label="Filter by category"
        >
          <option value="">All Categories</option>
          {Object.entries(CATEGORY_CONFIG).map(([key, conf]) => (
            <option key={key} value={key}>
              {conf.label}
            </option>
          ))}
        </select>
      </div>

      <div
        className="flex gap-1 border-b border-white/10 overflow-x-auto"
        role="tablist"
        aria-label="Adversarial testing sections"
      >
        {tabs.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`tabpanel-${tab.id}`}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-cyan-400 text-cyan-400"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:border-white/20"
              }`}
            >
              <TabIcon className="h-3.5 w-3.5" aria-hidden="true" />
              {tab.label}
              {tab.count !== undefined && (
                <Badge variant="outline" className="text-[9px] px-1.5 py-0 h-4 ml-1 bg-white/5 border-white/10">
                  {tab.count}
                </Badge>
              )}
            </button>
          );
        })}
      </div>

      <div role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={activeTab}>
        {activeTab === "library" && (
          <div className="space-y-3">
            {libraryLoading ? (
              Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-28" />)
            ) : filteredLibrary.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="py-12 text-center">
                  <Bug className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">
                    {searchQuery || domainFilter || categoryFilter
                      ? "No test cases match your filters. Try adjusting your search criteria."
                      : "No attack test cases available yet."}
                  </p>
                </CardContent>
              </Card>
            ) : (
              filteredLibrary.map((tc) => (
                <TestCaseCard
                  key={tc.id}
                  tc={tc}
                  isExpanded={expandedTests.has(tc.id)}
                  onToggle={() => toggleTestExpand(tc.id)}
                  onRun={() => handleRunTest(tc.id)}
                  isRunning={runningTests.has(tc.id)}
                />
              ))
            )}
          </div>
        )}

        {activeTab === "executions" && (
          <div className="space-y-2">
            {executionsLoading ? (
              Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-16" />)
            ) : filteredExecutions.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="py-12 text-center">
                  <Play className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">
                    {searchQuery || domainFilter || categoryFilter
                      ? "No executions match your filters."
                      : "No test executions yet. Run a test from the Attack Library tab to get started."}
                  </p>
                </CardContent>
              </Card>
            ) : (
              filteredExecutions.map((exec) => <ExecutionRow key={exec.id} execution={exec} />)
            )}
          </div>
        )}

        {activeTab === "schedules" && (
          <div className="space-y-3">
            {schedulesLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24" />)
            ) : (schedules || []).length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="py-12 text-center">
                  <Calendar className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">
                    No scheduled probes configured yet. Create a schedule to automate recurring adversarial tests.
                  </p>
                </CardContent>
              </Card>
            ) : (
              (schedules || []).map((schedule) => (
                <ScheduleCard
                  key={schedule.id}
                  schedule={schedule}
                  onToggle={() => toggleScheduleMutation.mutate({ id: schedule.id, enabled: !schedule.enabled })}
                  onDelete={() => deleteScheduleMutation.mutate(schedule.id)}
                />
              ))
            )}
          </div>
        )}

        {activeTab === "remediations" && (
          <div className="space-y-3">
            {remediationsLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24" />)
            ) : filteredRemediations.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="py-12 text-center">
                  <ListChecks className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">
                    {searchQuery || categoryFilter
                      ? "No remediations match your filters."
                      : "No open remediations. All adversarial tests are passing!"}
                  </p>
                </CardContent>
              </Card>
            ) : (
              filteredRemediations.map((item) => (
                <RemediationCard
                  key={item.id}
                  item={item}
                  onRetest={() => handleRetest(item.id)}
                  isRetesting={retestingRemediations.has(item.id)}
                  onUpdateStatus={(status) => updateRemediationMutation.mutate({ id: item.id, status })}
                />
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
