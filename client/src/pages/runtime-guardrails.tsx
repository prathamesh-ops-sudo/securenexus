import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Activity,
  Zap,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Eye,
  Play,
  Lock,
  Unlock,
  ChevronDown,
  ChevronRight,
  Search,
  FlaskConical,
  BarChart3,
  Timer,
  Bot,
  Globe,
  Key,
  Database,
  Terminal,
  FileEdit,
  Webhook,
  Radio,
  Layers,
  TrendingUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";

interface PolicyCondition {
  field: string;
  operator: string;
  value: string | number | string[];
}

interface PolicyRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  scope: string;
  actions: string[];
  mode: string;
  priority: number;
  conditions: PolicyCondition[];
  verdict: string;
  rateLimit: { maxRequests: number; windowSeconds: number } | null;
  tags: string[];
  version: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

interface PolicyDecision {
  id: string;
  orgId: string;
  policyId: string;
  policyName: string;
  policyVersion: number;
  action: string;
  verdict: string;
  mode: string;
  latencyMs: number;
  requestContext: Record<string, unknown>;
  matchedConditions: string[];
  timestamp: string;
  actorId: string;
  actorType: string;
  resourceId: string;
  resourceType: string;
  reason: string;
}

interface BlastRadius {
  affectedAgents: number;
  affectedWorkflows: number;
  affectedApiCalls: number;
  estimatedBlockRate: number;
  impactedScopes: string[];
  riskLevel: string;
}

interface PolicySimulation {
  id: string;
  orgId: string;
  policyId: string;
  policyName: string;
  simulatedAction: string;
  inputContext: Record<string, unknown>;
  expectedVerdict: string;
  actualVerdict: string;
  blastRadius: BlastRadius;
  dryRunAt: string;
  runBy: string;
}

interface EmergencyOverride {
  id: string;
  orgId: string;
  policyId: string;
  policyName: string;
  requestedBy: string;
  requestedAt: string;
  reason: string;
  status: string;
  approvedBy: string | null;
  approvedAt: string | null;
  expiresAt: string;
  timeboxMinutes: number;
  auditTrail: { action: string; actor: string; timestamp: string }[];
}

interface GuardrailStats {
  totalPolicies: number;
  activePolicies: number;
  dryRunPolicies: number;
  disabledPolicies: number;
  decisionsToday: number;
  allowedToday: number;
  deniedToday: number;
  quarantinedToday: number;
  avgLatencyMs: number;
  simulationsRun: number;
  activeOverrides: number;
  byScope: Record<string, number>;
  byAction: Record<string, number>;
  topBlockedActions: { action: string; count: number }[];
}

const MODE_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  enforce: { label: "Enforce", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: ShieldCheck },
  dry_run: { label: "Dry Run", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", icon: Eye },
  audit_only: { label: "Audit", color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Activity },
  disabled: { label: "Disabled", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30", icon: ShieldOff },
};

const VERDICT_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  allow: { label: "Allow", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
  deny: { label: "Deny", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: XCircle },
  quarantine: { label: "Quarantine", color: "bg-amber-500/20 text-amber-400 border-amber-500/30", icon: Lock },
};

const SCOPE_CONFIG: Record<string, { label: string; icon: typeof Shield }> = {
  ai_agent: { label: "AI Agent", icon: Bot },
  tool_api: { label: "Tool / API", icon: Zap },
  browser_workflow: { label: "Browser", icon: Globe },
  secret_egress: { label: "Secret Egress", icon: Key },
  data_pipeline: { label: "Data Pipeline", icon: Database },
  global: { label: "Global", icon: Layers },
};

const ACTION_ICONS: Record<string, typeof Shield> = {
  ai_agent_invoke: Bot,
  ai_agent_tool_call: Zap,
  api_outbound_call: Globe,
  browser_navigation: Globe,
  secret_access: Key,
  data_egress: Radio,
  file_write: FileEdit,
  shell_exec: Terminal,
  db_query: Database,
  webhook_dispatch: Webhook,
};

const OVERRIDE_STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  pending: { label: "Pending", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  approved: { label: "Approved", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  denied: { label: "Denied", color: "bg-red-500/20 text-red-400 border-red-500/30" },
  expired: { label: "Expired", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
};

type TabId = "policies" | "decisions" | "simulations" | "overrides";

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

function PolicyCard({
  policy,
  isExpanded,
  onToggle,
}: {
  policy: PolicyRule;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const modeConf = MODE_CONFIG[policy.mode] || MODE_CONFIG.disabled;
  const verdictConf = VERDICT_CONFIG[policy.verdict] || VERDICT_CONFIG.allow;
  const scopeConf = SCOPE_CONFIG[policy.scope] || SCOPE_CONFIG.global;
  const ModeIcon = modeConf.icon;
  const ScopeIcon = scopeConf.icon;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button onClick={onToggle} className="w-full text-left p-4 focus:outline-none">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <ScopeIcon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{policy.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${modeConf.color}`}>
                  <ModeIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {modeConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  {verdictConf.label}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{policy.description}</p>
              <div className="flex items-center gap-2 mt-2 flex-wrap">
                <span className="text-[10px] text-muted-foreground">Priority: {policy.priority}</span>
                <span className="text-[10px] text-muted-foreground">v{policy.version}</span>
                {policy.rateLimit && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/10 text-purple-400 border-purple-500/20"
                  >
                    {policy.rateLimit.maxRequests}/{policy.rateLimit.windowSeconds}s
                  </Badge>
                )}
                {policy.tags.map((tag) => (
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
          <div className="shrink-0 mt-1">
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
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Covered Actions</p>
            <div className="flex flex-wrap gap-1.5">
              {policy.actions.map((action) => {
                const ActionIcon = ACTION_ICONS[action] || Zap;
                return (
                  <Badge key={action} variant="outline" className="text-[10px] px-2 py-0.5 bg-white/5 border-white/10">
                    <ActionIcon className="h-3 w-3 mr-1" aria-hidden="true" />
                    {action.replace(/_/g, " ")}
                  </Badge>
                );
              })}
            </div>
          </div>
          {policy.conditions.length > 0 && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Conditions</p>
              <div className="space-y-1">
                {policy.conditions.map((cond, i) => (
                  <div key={i} className="text-xs font-mono bg-black/30 rounded px-2 py-1 text-cyan-300/80">
                    {cond.field} <span className="text-muted-foreground">{cond.operator}</span>{" "}
                    <span className="text-amber-400">{JSON.stringify(cond.value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
            <span>Scope: {scopeConf.label}</span>
            <span>Created: {new Date(policy.createdAt).toLocaleDateString()}</span>
            <span>Updated: {new Date(policy.updatedAt).toLocaleDateString()}</span>
            <span>By: {policy.createdBy}</span>
          </div>
        </div>
      )}
    </Card>
  );
}

function DecisionRow({ decision }: { decision: PolicyDecision }) {
  const [expanded, setExpanded] = useState(false);
  const verdictConf = VERDICT_CONFIG[decision.verdict] || VERDICT_CONFIG.allow;
  const VerdictIcon = verdictConf.icon;
  const ActionIcon = ACTION_ICONS[decision.action] || Zap;

  return (
    <div className="glass-card border border-white/5 rounded-lg hover:border-cyan-500/15 transition-colors">
      <button onClick={() => setExpanded(!expanded)} className="w-full text-left p-3 focus:outline-none">
        <div className="flex items-center gap-3">
          <VerdictIcon
            className={`h-4 w-4 shrink-0 ${decision.verdict === "allow" ? "text-emerald-400" : decision.verdict === "deny" ? "text-red-400" : "text-amber-400"}`}
            aria-hidden="true"
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium truncate">{decision.policyName}</span>
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                {verdictConf.label}
              </Badge>
            </div>
            <div className="flex items-center gap-2 mt-0.5 text-[10px] text-muted-foreground">
              <ActionIcon className="h-3 w-3" aria-hidden="true" />
              <span>{decision.action.replace(/_/g, " ")}</span>
              <span>|</span>
              <span>
                {decision.actorType}: {decision.actorId}
              </span>
              <span>|</span>
              <Timer className="h-3 w-3" aria-hidden="true" />
              <span>{decision.latencyMs}ms</span>
            </div>
          </div>
          <span className="text-[10px] text-muted-foreground shrink-0">
            {new Date(decision.timestamp).toLocaleTimeString()}
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
          <p className="text-xs text-cyan-300/80">{decision.reason}</p>
          {decision.matchedConditions.length > 0 && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Matched Conditions</p>
              {decision.matchedConditions.map((c, i) => (
                <div key={i} className="text-[10px] font-mono bg-black/30 rounded px-2 py-0.5 text-amber-300/80 mb-0.5">
                  {c}
                </div>
              ))}
            </div>
          )}
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
            <span>
              Resource: {decision.resourceType}/{decision.resourceId}
            </span>
            <span>Policy v{decision.policyVersion}</span>
            <span>Mode: {decision.mode}</span>
          </div>
          {Object.keys(decision.requestContext).length > 0 && (
            <details className="text-[10px]">
              <summary className="text-muted-foreground cursor-pointer hover:text-cyan-400">Request Context</summary>
              <pre className="mt-1 bg-black/40 rounded p-2 text-cyan-300/70 overflow-x-auto text-[9px]">
                {JSON.stringify(decision.requestContext, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function SimulationCard({ sim }: { sim: PolicySimulation }) {
  const [expanded, setExpanded] = useState(false);
  const match = sim.expectedVerdict === sim.actualVerdict;
  const riskColors: Record<string, string> = {
    low: "text-emerald-400",
    medium: "text-yellow-400",
    high: "text-orange-400",
    critical: "text-red-400",
  };

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/15 transition-colors">
      <button onClick={() => setExpanded(!expanded)} className="w-full text-left p-4 focus:outline-none">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className={`p-2 rounded-lg ${match ? "bg-emerald-500/10" : "bg-red-500/10"}`}>
              <FlaskConical className={`h-4 w-4 ${match ? "text-emerald-400" : "text-red-400"}`} aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{sim.policyName}</h3>
                <Badge
                  variant="outline"
                  className={`text-[9px] px-1.5 py-0 h-4 ${match ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-red-500/20 text-red-400 border-red-500/30"}`}
                >
                  {match ? "Match" : "Mismatch"}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                {sim.simulatedAction.replace(/_/g, " ")} — Expected: {sim.expectedVerdict}, Got: {sim.actualVerdict}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className={`text-xs font-medium ${riskColors[sim.blastRadius.riskLevel] || "text-muted-foreground"}`}>
              {sim.blastRadius.riskLevel}
            </span>
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
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Blast Radius</p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="bg-black/30 rounded-lg p-2 text-center">
                <p className="text-lg font-bold">{sim.blastRadius.affectedAgents}</p>
                <p className="text-[9px] text-muted-foreground">Agents</p>
              </div>
              <div className="bg-black/30 rounded-lg p-2 text-center">
                <p className="text-lg font-bold">{sim.blastRadius.affectedWorkflows}</p>
                <p className="text-[9px] text-muted-foreground">Workflows</p>
              </div>
              <div className="bg-black/30 rounded-lg p-2 text-center">
                <p className="text-lg font-bold">{sim.blastRadius.affectedApiCalls}</p>
                <p className="text-[9px] text-muted-foreground">API Calls</p>
              </div>
              <div className="bg-black/30 rounded-lg p-2 text-center">
                <p className="text-lg font-bold">{Math.round(sim.blastRadius.estimatedBlockRate * 100)}%</p>
                <p className="text-[9px] text-muted-foreground">Block Rate</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground flex-wrap">
            <span>Scopes: {sim.blastRadius.impactedScopes.join(", ")}</span>
            <span>Run by: {sim.runBy}</span>
            <span>{new Date(sim.dryRunAt).toLocaleString()}</span>
          </div>
        </div>
      )}
    </Card>
  );
}

function OverrideCard({ override }: { override: EmergencyOverride }) {
  const [expanded, setExpanded] = useState(false);
  const statusConf = OVERRIDE_STATUS_CONFIG[override.status] || OVERRIDE_STATUS_CONFIG.pending;
  const isActive = override.status === "approved" && new Date(override.expiresAt) > new Date();

  return (
    <Card
      className={`glass-card border-white/5 hover:border-cyan-500/15 transition-colors ${isActive ? "border-amber-500/30" : ""}`}
    >
      <button onClick={() => setExpanded(!expanded)} className="w-full text-left p-4 focus:outline-none">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className={`p-2 rounded-lg ${isActive ? "bg-amber-500/15" : "bg-white/5"}`}>
              {isActive ? (
                <Unlock className="h-4 w-4 text-amber-400" aria-hidden="true" />
              ) : (
                <Lock className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{override.policyName}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${statusConf.color}`}>
                  {statusConf.label}
                </Badge>
                {isActive && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-amber-500/20 text-amber-400 border-amber-500/30 animate-pulse"
                  >
                    ACTIVE
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{override.reason}</p>
              <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                <span>By: {override.requestedBy}</span>
                <span>Timebox: {override.timeboxMinutes}m</span>
                <span>Expires: {new Date(override.expiresAt).toLocaleString()}</span>
              </div>
            </div>
          </div>
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 border-t border-white/5 pt-3 space-y-3">
          {override.approvedBy && (
            <div className="text-xs text-emerald-400">
              Approved by: {override.approvedBy} at {new Date(override.approvedAt || "").toLocaleString()}
            </div>
          )}
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Audit Trail</p>
            <div className="space-y-1">
              {override.auditTrail.map((entry, i) => (
                <div key={i} className="flex items-center gap-2 text-[10px]">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400/50" />
                  <span className="text-muted-foreground">{new Date(entry.timestamp).toLocaleString()}</span>
                  <span className="font-medium">{entry.action.replace(/_/g, " ")}</span>
                  <span className="text-muted-foreground">by {entry.actor}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function ScopeBreakdown({ byScope }: { byScope: Record<string, number> }) {
  const entries = Object.entries(byScope).sort(([, a], [, b]) => b - a);
  if (entries.length === 0) return null;
  const max = Math.max(...entries.map(([, v]) => v), 1);

  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="p-3 pb-2">
        <CardTitle className="text-xs font-medium flex items-center gap-2">
          <Layers className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
          Policies by Scope
        </CardTitle>
      </CardHeader>
      <CardContent className="p-3 pt-0 space-y-2">
        {entries.map(([scope, count]) => {
          const conf = SCOPE_CONFIG[scope] || SCOPE_CONFIG.global;
          const ScopeIcon = conf.icon;
          return (
            <div key={scope} className="flex items-center gap-2">
              <ScopeIcon className="h-3.5 w-3.5 text-cyan-400/60 shrink-0" aria-hidden="true" />
              <span className="text-[10px] w-20 truncate">{conf.label}</span>
              <div className="flex-1 h-2 bg-black/30 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400 rounded-full transition-all"
                  style={{ width: `${(count / max) * 100}%` }}
                />
              </div>
              <span className="text-[10px] text-muted-foreground w-6 text-right">{count}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function TopBlockedActions({ actions }: { actions: { action: string; count: number }[] }) {
  if (actions.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="p-3 pb-2">
          <CardTitle className="text-xs font-medium flex items-center gap-2">
            <ShieldAlert className="h-3.5 w-3.5 text-red-400" aria-hidden="true" />
            Top Blocked Actions
          </CardTitle>
        </CardHeader>
        <CardContent className="p-3 pt-0">
          <p className="text-[10px] text-muted-foreground">No blocked actions today</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="p-3 pb-2">
        <CardTitle className="text-xs font-medium flex items-center gap-2">
          <ShieldAlert className="h-3.5 w-3.5 text-red-400" aria-hidden="true" />
          Top Blocked Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="p-3 pt-0 space-y-2">
        {actions.map(({ action, count }) => {
          const ActionIcon = ACTION_ICONS[action] || Zap;
          return (
            <div key={action} className="flex items-center gap-2">
              <ActionIcon className="h-3.5 w-3.5 text-red-400/60 shrink-0" aria-hidden="true" />
              <span className="text-[10px] flex-1 truncate">{action.replace(/_/g, " ")}</span>
              <Badge
                variant="outline"
                className="text-[9px] px-1.5 py-0 h-4 bg-red-500/10 text-red-400 border-red-500/20"
              >
                {count}
              </Badge>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

export default function RuntimeGuardrailsPage() {
  const [activeTab, setActiveTab] = useState<TabId>("policies");
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedPolicies, setExpandedPolicies] = useState<Set<string>>(new Set());
  const [modeFilter, setModeFilter] = useState<string>("all");
  const [scopeFilter, setScopeFilter] = useState<string>("all");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");

  const { data: policies, isLoading: policiesLoading } = useQuery<PolicyRule[]>({
    queryKey: ["/api/runtime-guardrails/policies"],
  });

  const { data: stats, isLoading: statsLoading } = useQuery<GuardrailStats>({
    queryKey: ["/api/runtime-guardrails/stats"],
  });

  const { data: decisions, isLoading: decisionsLoading } = useQuery<PolicyDecision[]>({
    queryKey: ["/api/runtime-guardrails/decisions"],
    enabled: activeTab === "decisions",
  });

  const { data: simulations, isLoading: simulationsLoading } = useQuery<PolicySimulation[]>({
    queryKey: ["/api/runtime-guardrails/simulations"],
    enabled: activeTab === "simulations",
  });

  const { data: overrides, isLoading: overridesLoading } = useQuery<EmergencyOverride[]>({
    queryKey: ["/api/runtime-guardrails/overrides"],
    enabled: activeTab === "overrides",
  });

  const togglePolicy = (id: string) => {
    setExpandedPolicies((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredPolicies = (policies || []).filter((p) => {
    if (modeFilter !== "all" && p.mode !== modeFilter) return false;
    if (scopeFilter !== "all" && p.scope !== scopeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        p.name.toLowerCase().includes(term) ||
        p.description.toLowerCase().includes(term) ||
        p.tags.some((t) => t.toLowerCase().includes(term)) ||
        p.actions.some((a) => a.toLowerCase().includes(term))
      );
    }
    return true;
  });

  const filteredDecisions = (decisions || []).filter((d) => {
    if (verdictFilter !== "all" && d.verdict !== verdictFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        d.policyName.toLowerCase().includes(term) ||
        d.action.toLowerCase().includes(term) ||
        d.actorId.toLowerCase().includes(term) ||
        d.reason.toLowerCase().includes(term)
      );
    }
    return true;
  });

  const tabs: { id: TabId; label: string; icon: typeof Shield }[] = [
    { id: "policies", label: "Policies", icon: Shield },
    { id: "decisions", label: "Decision Log", icon: Activity },
    { id: "simulations", label: "Simulations", icon: FlaskConical },
    { id: "overrides", label: "Overrides", icon: Lock },
  ];

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight gradient-text-brand">Runtime Guardrails</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Policy-driven runtime control plane — enforce, simulate, and override security policies across AI agents,
            APIs, and data flows
          </p>
        </div>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-lg" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard label="Total Policies" value={stats.totalPolicies} icon={Shield} />
          <StatCard
            label="Active Enforcing"
            value={stats.activePolicies}
            icon={ShieldCheck}
            accent="bg-emerald-500/10"
          />
          <StatCard label="Decisions Today" value={stats.decisionsToday} icon={Activity} accent="bg-blue-500/10" />
          <StatCard label="Denied Today" value={stats.deniedToday} icon={XCircle} accent="bg-red-500/10" />
          <StatCard label="Avg Latency" value={`${stats.avgLatencyMs}ms`} icon={Timer} accent="bg-purple-500/10" />
          <StatCard label="Active Overrides" value={stats.activeOverrides} icon={Unlock} accent="bg-amber-500/10" />
        </div>
      ) : null}

      <div className="flex items-center gap-3 flex-wrap">
        {tabs.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === tab.id
                  ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                  : "bg-white/5 text-muted-foreground hover:bg-white/10 border border-white/5"
              }`}
            >
              <TabIcon className="h-3.5 w-3.5" aria-hidden="true" />
              {tab.label}
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder={activeTab === "policies" ? "Search policies, tags, actions..." : "Search decisions, actors..."}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 h-8 text-xs bg-white/5 border-white/10"
          />
        </div>
        {activeTab === "policies" && (
          <>
            <select
              value={modeFilter}
              onChange={(e) => setModeFilter(e.target.value)}
              className="h-8 px-2 text-xs bg-white/5 border border-white/10 rounded-md text-foreground"
              aria-label="Filter by mode"
            >
              <option value="all">All Modes</option>
              <option value="enforce">Enforce</option>
              <option value="dry_run">Dry Run</option>
              <option value="audit_only">Audit Only</option>
              <option value="disabled">Disabled</option>
            </select>
            <select
              value={scopeFilter}
              onChange={(e) => setScopeFilter(e.target.value)}
              className="h-8 px-2 text-xs bg-white/5 border border-white/10 rounded-md text-foreground"
              aria-label="Filter by scope"
            >
              <option value="all">All Scopes</option>
              <option value="ai_agent">AI Agent</option>
              <option value="tool_api">Tool / API</option>
              <option value="browser_workflow">Browser</option>
              <option value="secret_egress">Secret Egress</option>
              <option value="data_pipeline">Data Pipeline</option>
              <option value="global">Global</option>
            </select>
          </>
        )}
        {activeTab === "decisions" && (
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="h-8 px-2 text-xs bg-white/5 border border-white/10 rounded-md text-foreground"
            aria-label="Filter by verdict"
          >
            <option value="all">All Verdicts</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="quarantine">Quarantine</option>
          </select>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 space-y-3">
          {activeTab === "policies" && (
            <>
              {policiesLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-28 rounded-lg" />
                  ))}
                </div>
              ) : filteredPolicies.length === 0 ? (
                <Card className="glass-card border-white/5 p-8 text-center">
                  <Shield className="h-10 w-10 mx-auto text-muted-foreground/30 mb-3" aria-hidden="true" />
                  <p className="text-sm text-muted-foreground">No policies match your filters</p>
                </Card>
              ) : (
                filteredPolicies.map((policy) => (
                  <PolicyCard
                    key={policy.id}
                    policy={policy}
                    isExpanded={expandedPolicies.has(policy.id)}
                    onToggle={() => togglePolicy(policy.id)}
                  />
                ))
              )}
            </>
          )}

          {activeTab === "decisions" && (
            <>
              {decisionsLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 rounded-lg" />
                  ))}
                </div>
              ) : filteredDecisions.length === 0 ? (
                <Card className="glass-card border-white/5 p-8 text-center">
                  <Activity className="h-10 w-10 mx-auto text-muted-foreground/30 mb-3" aria-hidden="true" />
                  <p className="text-sm text-muted-foreground">No decision logs found</p>
                </Card>
              ) : (
                filteredDecisions.map((d) => <DecisionRow key={d.id} decision={d} />)
              )}
            </>
          )}

          {activeTab === "simulations" && (
            <>
              {simulationsLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={i} className="h-24 rounded-lg" />
                  ))}
                </div>
              ) : (simulations || []).length === 0 ? (
                <Card className="glass-card border-white/5 p-8 text-center">
                  <FlaskConical className="h-10 w-10 mx-auto text-muted-foreground/30 mb-3" aria-hidden="true" />
                  <p className="text-sm text-muted-foreground">No simulations run yet</p>
                  <p className="text-[10px] text-muted-foreground mt-1">
                    Run a dry-run simulation to see blast radius before enforcing a policy
                  </p>
                </Card>
              ) : (
                (simulations || []).map((s) => <SimulationCard key={s.id} sim={s} />)
              )}
            </>
          )}

          {activeTab === "overrides" && (
            <>
              {overridesLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 2 }).map((_, i) => (
                    <Skeleton key={i} className="h-28 rounded-lg" />
                  ))}
                </div>
              ) : (overrides || []).length === 0 ? (
                <Card className="glass-card border-white/5 p-8 text-center">
                  <Lock className="h-10 w-10 mx-auto text-muted-foreground/30 mb-3" aria-hidden="true" />
                  <p className="text-sm text-muted-foreground">No emergency overrides</p>
                  <p className="text-[10px] text-muted-foreground mt-1">
                    Emergency overrides require dual-approval and are strictly timeboxed
                  </p>
                </Card>
              ) : (
                (overrides || []).map((o) => <OverrideCard key={o.id} override={o} />)
              )}
            </>
          )}
        </div>

        <div className="space-y-3">
          {stats && <ScopeBreakdown byScope={stats.byScope} />}
          {stats && <TopBlockedActions actions={stats.topBlockedActions} />}

          <Card className="glass-card border-white/5">
            <CardHeader className="p-3 pb-2">
              <CardTitle className="text-xs font-medium flex items-center gap-2">
                <TrendingUp className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
                Decision Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3 pt-0 space-y-2">
              {stats ? (
                <>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                    <span className="text-[10px] flex-1">Allowed</span>
                    <span className="text-xs font-bold text-emerald-400">{stats.allowedToday}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <XCircle className="h-3.5 w-3.5 text-red-400" aria-hidden="true" />
                    <span className="text-[10px] flex-1">Denied</span>
                    <span className="text-xs font-bold text-red-400">{stats.deniedToday}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Lock className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
                    <span className="text-[10px] flex-1">Quarantined</span>
                    <span className="text-xs font-bold text-amber-400">{stats.quarantinedToday}</span>
                  </div>
                  <div className="border-t border-white/5 pt-2 mt-2">
                    <div className="flex items-center gap-2">
                      <Play className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                      <span className="text-[10px] flex-1">Dry-Run Policies</span>
                      <span className="text-xs font-bold text-blue-400">{stats.dryRunPolicies}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <FlaskConical className="h-3.5 w-3.5 text-purple-400" aria-hidden="true" />
                      <span className="text-[10px] flex-1">Simulations Run</span>
                      <span className="text-xs font-bold text-purple-400">{stats.simulationsRun}</span>
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-[10px] text-muted-foreground">Loading...</p>
              )}
            </CardContent>
          </Card>

          <Card className="glass-card border-white/5">
            <CardHeader className="p-3 pb-2">
              <CardTitle className="text-xs font-medium flex items-center gap-2">
                <BarChart3 className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
                Enforcement Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3 pt-0">
              {stats ? (
                <div className="space-y-1.5 text-[10px]">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Enforcing</span>
                    <span className="font-medium text-emerald-400">{stats.activePolicies}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Dry Run</span>
                    <span className="font-medium text-yellow-400">{stats.dryRunPolicies}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Disabled</span>
                    <span className="font-medium text-zinc-400">{stats.disabledPolicies}</span>
                  </div>
                  <div className="flex justify-between border-t border-white/5 pt-1.5">
                    <span className="text-muted-foreground">Active Overrides</span>
                    <span className="font-medium text-amber-400">{stats.activeOverrides}</span>
                  </div>
                </div>
              ) : (
                <p className="text-[10px] text-muted-foreground">Loading...</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
