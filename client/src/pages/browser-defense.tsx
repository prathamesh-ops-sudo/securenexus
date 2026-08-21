import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ApiQueryError } from "@/components/api-query-state";
import { apiQuery, apiRequest, hasObjectKeys, isArrayOf } from "@/lib/queryClient";
import {
  Shield,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  Globe,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  Eye,
  EyeOff,
  Fingerprint,
  Zap,
  ArrowRight,
  Clock,
  Activity,
  FileWarning,
  Terminal,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Settings,
  Trash2,
  Ban,
  Route,
  MonitorSmartphone,
  Wifi,
  WifiOff,
  Bug,
  Crosshair,
  MousePointer,
  Plus,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

interface BrowserSession {
  id: string;
  orgId: string;
  agentId: string;
  agentName: string;
  contextId: string;
  originUrl: string;
  state: string;
  isolationLevel: string;
  tokensIssued: number;
  tokensBound: number;
  lastActivityAt: string;
  createdAt: string;
  expiresAt: string;
  metadata: Record<string, string>;
}

interface DomEvent {
  id: string;
  orgId: string;
  sessionId: string;
  agentId: string;
  eventType: string;
  targetSelector: string;
  actionClassification: string;
  severity: string;
  verdict: string;
  details: string;
  rawPayloadHash: string;
  stepUpRequired: boolean;
  stepUpCompleted: boolean;
  timestamp: string;
}

interface EgressRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  direction: string;
  domainPattern: string;
  portRange: string;
  protocol: string;
  action: string;
  enabled: boolean;
  hitCount: number;
  lastHitAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface TrustedPath {
  id: string;
  orgId: string;
  name: string;
  description: string;
  steps: Array<{
    order: number;
    actionType: string;
    targetPattern: string;
    requiredContext: string[];
    allowSkip: boolean;
  }>;
  enforceOrder: boolean;
  maxDurationMs: number;
  failAction: string;
  enabled: boolean;
  executionCount: number;
  deviationCount: number;
  createdAt: string;
  updatedAt: string;
}

interface InjectionPattern {
  id: string;
  orgId: string;
  name: string;
  category: string;
  pattern: string;
  severity: string;
  action: string;
  description: string;
  falsePositiveRate: number;
  detectionCount: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface BrowserDefenseStats {
  totalSessions: number;
  activeSessions: number;
  totalEgressRules: number;
  totalTrustedPaths: number;
}

const SEVERITY_CONFIG: Record<string, { label: string; color: string }> = {
  info: { label: "Info", color: "bg-slate-500/20 text-slate-400 border-slate-500/30" },
  low: { label: "Low", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  medium: { label: "Medium", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  high: { label: "High", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  critical: { label: "Critical", color: "bg-red-500/20 text-red-400 border-red-500/30" },
};

const VERDICT_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  allow: { label: "Allow", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
  block: { label: "Block", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: XCircle },
  challenge: { label: "Challenge", color: "bg-amber-500/20 text-amber-400 border-amber-500/30", icon: Fingerprint },
  log_only: { label: "Log Only", color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Eye },
};

const SESSION_STATE_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  active: { label: "Active", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
  isolated: { label: "Isolated", color: "bg-amber-500/20 text-amber-400 border-amber-500/30", icon: Lock },
  terminated: { label: "Terminated", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: Ban },
  expired: { label: "Expired", color: "bg-slate-500/20 text-slate-400 border-slate-500/30", icon: Clock },
};

const CATEGORY_CONFIG: Record<string, { label: string; icon: typeof Shield }> = {
  dom_injection: { label: "DOM Injection", icon: Bug },
  prompt_injection: { label: "Prompt Injection", icon: Terminal },
  egress_violation: { label: "Egress Violation", icon: WifiOff },
  path_deviation: { label: "Path Deviation", icon: Route },
  session_hijack: { label: "Session Hijack", icon: ShieldAlert },
  token_reuse: { label: "Token Reuse", icon: Unlock },
  xss_attempt: { label: "XSS Attempt", icon: FileWarning },
  clickjacking: { label: "Clickjacking", icon: MousePointer },
  benign: { label: "Benign", icon: CheckCircle2 },
};

type TabId = "sessions" | "events" | "egress" | "paths" | "patterns";

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

function SessionCard({
  session,
  onIsolate,
  onTerminate,
  isActing,
}: {
  session: BrowserSession;
  onIsolate: () => void;
  onTerminate: () => void;
  isActing: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const stateConf = SESSION_STATE_CONFIG[session.state] || SESSION_STATE_CONFIG.active;
  const StateIcon = stateConf.icon;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <MonitorSmartphone className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{session.agentName}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${stateConf.color}`}>
                  <StateIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {stateConf.label}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/10 text-cyan-400/70 border-cyan-500/20"
                >
                  {session.isolationLevel}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1 truncate">{session.originUrl}</p>
              <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                <span className="text-[10px] text-muted-foreground">Context: {session.contextId.slice(0, 12)}...</span>
                <span className="text-[10px] text-muted-foreground">
                  Tokens: {session.tokensBound}/{session.tokensIssued}
                </span>
                <span className="text-[10px] text-muted-foreground">
                  Last active: {new Date(session.lastActivityAt).toLocaleString()}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0 mt-1">
            {session.state === "active" && (
              <>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-[10px] hover:bg-amber-500/10 hover:text-amber-400"
                  onClick={(e) => {
                    e.stopPropagation();
                    onIsolate();
                  }}
                  disabled={isActing}
                  aria-label={`Isolate session: ${session.agentName}`}
                >
                  <Lock className="h-3 w-3" />
                  <span className="ml-1">Isolate</span>
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-[10px] hover:bg-red-500/10 hover:text-red-400"
                  onClick={(e) => {
                    e.stopPropagation();
                    onTerminate();
                  }}
                  disabled={isActing}
                  aria-label={`Terminate session: ${session.agentName}`}
                >
                  <Ban className="h-3 w-3" />
                  <span className="ml-1">Kill</span>
                </Button>
              </>
            )}
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-white/5 space-y-2">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-muted-foreground">Session ID:</span>{" "}
              <code className="text-[9px] bg-white/5 px-1 py-0.5 rounded">{session.id}</code>
            </div>
            <div>
              <span className="text-muted-foreground">Agent ID:</span> {session.agentId}
            </div>
            <div>
              <span className="text-muted-foreground">Created:</span> {new Date(session.createdAt).toLocaleString()}
            </div>
            <div>
              <span className="text-muted-foreground">Expires:</span> {new Date(session.expiresAt).toLocaleString()}
            </div>
            <div>
              <span className="text-muted-foreground">Viewport:</span> {session.metadata.viewport}
            </div>
            <div>
              <span className="text-muted-foreground">User Agent:</span> {session.metadata.userAgent}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function DomEventRow({ evt }: { evt: DomEvent }) {
  const [expanded, setExpanded] = useState(false);
  const sevConf = SEVERITY_CONFIG[evt.severity] || SEVERITY_CONFIG.info;
  const verdictConf = VERDICT_CONFIG[evt.verdict] || VERDICT_CONFIG.allow;
  const VerdictIcon = verdictConf.icon;
  const catConf = CATEGORY_CONFIG[evt.actionClassification] || CATEGORY_CONFIG.benign;
  const CatIcon = catConf.icon;

  return (
    <div className="border-b border-white/5 last:border-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left px-4 py-3 hover:bg-white/[0.02] transition-colors focus:outline-none focus:ring-1 focus:ring-cyan-500/30"
      >
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <CatIcon
              className={`h-4 w-4 shrink-0 ${evt.actionClassification === "benign" ? "text-emerald-400" : sevConf.color.split(" ")[1]}`}
              aria-hidden="true"
            />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-medium">{evt.eventType}</span>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  <VerdictIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {verdictConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                  {sevConf.label}
                </Badge>
                {evt.actionClassification !== "benign" && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/10 text-purple-400/70 border-purple-500/20"
                  >
                    {catConf.label}
                  </Badge>
                )}
                {evt.stepUpRequired && (
                  <Badge
                    variant="outline"
                    className={`text-[9px] px-1.5 py-0 h-4 ${evt.stepUpCompleted ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-amber-500/10 text-amber-400 border-amber-500/20"}`}
                  >
                    <Fingerprint className="h-2.5 w-2.5 mr-0.5" />
                    {evt.stepUpCompleted ? "Verified" : "Pending"}
                  </Badge>
                )}
              </div>
              <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{evt.targetSelector}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[10px] text-muted-foreground">{new Date(evt.timestamp).toLocaleString()}</span>
            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          </div>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-3 space-y-2 text-xs">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="text-muted-foreground">Details:</span> {evt.details}
            </div>
            <div>
              <span className="text-muted-foreground">Payload Hash:</span>{" "}
              <code className="text-[9px] bg-white/5 px-1 py-0.5 rounded">{evt.rawPayloadHash}</code>
            </div>
            <div>
              <span className="text-muted-foreground">Session:</span> {evt.sessionId}
            </div>
            <div>
              <span className="text-muted-foreground">Agent:</span> {evt.agentId}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function EgressRuleCard({
  rule,
  onDelete,
  onToggle,
  isDeleting,
}: {
  rule: EgressRule;
  onDelete: () => void;
  onToggle: () => void;
  isDeleting: boolean;
}) {
  const verdictConf = VERDICT_CONFIG[rule.action] || VERDICT_CONFIG.allow;
  const VerdictIcon = verdictConf.icon;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              {rule.action === "block" ? (
                <WifiOff className="h-4 w-4 text-red-400" aria-hidden="true" />
              ) : (
                <Wifi className="h-4 w-4 text-cyan-400" aria-hidden="true" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold">{rule.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  <VerdictIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {verdictConf.label}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/10 text-cyan-400/70 border-cyan-500/20"
                >
                  {rule.protocol.toUpperCase()}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/10 text-purple-400/70 border-purple-500/20"
                >
                  {rule.direction}
                </Badge>
                {!rule.enabled && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-slate-500/10 text-slate-400 border-slate-500/20"
                  >
                    Disabled
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">{rule.description}</p>
              <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                <span className="text-[10px] text-muted-foreground">
                  Domain: <code className="bg-white/5 px-1 py-0.5 rounded">{rule.domainPattern}</code>
                </span>
                <span className="text-[10px] text-muted-foreground">Port: {rule.portRange}</span>
                <span className="text-[10px] text-muted-foreground">Hits: {rule.hitCount}</span>
                {rule.lastHitAt && (
                  <span className="text-[10px] text-muted-foreground">
                    Last: {new Date(rule.lastHitAt).toLocaleString()}
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-cyan-500/10 hover:text-cyan-400"
              onClick={onToggle}
              aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
            >
              {rule.enabled ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-red-500/10 hover:text-red-400"
              onClick={onDelete}
              disabled={isDeleting}
              aria-label={`Delete rule: ${rule.name}`}
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function TrustedPathCard({ path }: { path: TrustedPath }) {
  const [expanded, setExpanded] = useState(false);
  const verdictConf = VERDICT_CONFIG[path.failAction] || VERDICT_CONFIG.block;
  const deviationRate =
    path.executionCount > 0 ? ((path.deviationCount / path.executionCount) * 100).toFixed(1) : "0.0";

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <Route className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold">{path.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  Fail: {verdictConf.label}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/10 text-cyan-400/70 border-cyan-500/20"
                >
                  {path.steps.length} steps
                </Badge>
                {path.enforceOrder && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/10 text-purple-400/70 border-purple-500/20"
                  >
                    Ordered
                  </Badge>
                )}
                {!path.enabled && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-slate-500/10 text-slate-400 border-slate-500/20"
                  >
                    Disabled
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">{path.description}</p>
              <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                <span className="text-[10px] text-muted-foreground">Executions: {path.executionCount}</span>
                <span className="text-[10px] text-muted-foreground">
                  Deviations: {path.deviationCount} ({deviationRate}%)
                </span>
                <span className="text-[10px] text-muted-foreground">
                  Max: {(path.maxDurationMs / 1000).toFixed(0)}s
                </span>
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
        <div className="px-4 pb-4 pt-1 border-t border-white/5">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Execution Steps</p>
          <div className="space-y-2">
            {path.steps.map((step, idx) => (
              <div key={idx} className="flex items-center gap-2 text-xs">
                <div className="w-6 h-6 rounded-full bg-cyan-500/10 flex items-center justify-center text-[10px] font-bold text-cyan-400 shrink-0">
                  {step.order}
                </div>
                <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <span className="font-medium">{step.actionType}</span>
                  <span className="text-muted-foreground ml-1">{step.targetPattern}</span>
                  {step.allowSkip && <span className="text-[10px] text-amber-400 ml-2">(skippable)</span>}
                </div>
                <div className="flex gap-1 shrink-0">
                  {step.requiredContext.map((ctx) => (
                    <Badge
                      key={ctx}
                      variant="outline"
                      className="text-[8px] px-1 py-0 h-3.5 bg-white/5 text-muted-foreground border-white/10"
                    >
                      {ctx}
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

function InjectionPatternCard({ pattern, onToggle }: { pattern: InjectionPattern; onToggle: () => void }) {
  const sevConf = SEVERITY_CONFIG[pattern.severity] || SEVERITY_CONFIG.medium;
  const verdictConf = VERDICT_CONFIG[pattern.action] || VERDICT_CONFIG.block;
  const catConf = CATEGORY_CONFIG[pattern.category] || CATEGORY_CONFIG.dom_injection;
  const CatIcon = catConf.icon;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <CatIcon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold">{pattern.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                  {sevConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  {verdictConf.label}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/10 text-purple-400/70 border-purple-500/20"
                >
                  {catConf.label}
                </Badge>
                {!pattern.enabled && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-slate-500/10 text-slate-400 border-slate-500/20"
                  >
                    Disabled
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">{pattern.description}</p>
              <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                <span className="text-[10px] text-muted-foreground">
                  Pattern:{" "}
                  <code className="bg-white/5 px-1 py-0.5 rounded text-[9px]">
                    {pattern.pattern.length > 50 ? pattern.pattern.slice(0, 50) + "..." : pattern.pattern}
                  </code>
                </span>
                <span className="text-[10px] text-muted-foreground">Detections: {pattern.detectionCount}</span>
                <span className="text-[10px] text-muted-foreground">
                  FP Rate: {(pattern.falsePositiveRate * 100).toFixed(0)}%
                </span>
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-[10px] hover:bg-cyan-500/10 hover:text-cyan-400 shrink-0"
            onClick={onToggle}
            aria-label={pattern.enabled ? "Disable pattern" : "Enable pattern"}
          >
            {pattern.enabled ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function ThreatCategoryChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const maxVal = Math.max(...entries.map(([, v]) => v), 1);

  if (entries.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Threats by Category</CardTitle>
        </CardHeader>
        <CardContent className="p-4 text-center text-xs text-muted-foreground">No threat data available</CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Threats by Category</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 p-4">
        {entries.map(([category, count]) => {
          const conf = CATEGORY_CONFIG[category] || { label: category, icon: Shield };
          const CIcon = conf.icon;
          return (
            <div key={category} className="flex items-center gap-2">
              <CIcon className="h-3 w-3 text-muted-foreground shrink-0" aria-hidden="true" />
              <span className="text-[10px] text-muted-foreground w-28 truncate">{conf.label}</span>
              <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500/60 to-blue-500/60 rounded-full"
                  style={{ width: `${(count / maxVal) * 100}%` }}
                />
              </div>
              <span className="text-[10px] font-mono text-muted-foreground w-8 text-right">{count}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function SeverityChart({ data }: { data: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const entries = order.filter((k) => data[k] !== undefined).map((k) => [k, data[k]] as [string, number]);
  const maxVal = Math.max(...entries.map(([, v]) => v), 1);

  if (entries.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Events by Severity</CardTitle>
        </CardHeader>
        <CardContent className="p-4 text-center text-xs text-muted-foreground">No event data available</CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Events by Severity</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 p-4">
        {entries.map(([severity, count]) => {
          const conf = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
          return (
            <div key={severity} className="flex items-center gap-2">
              <span className={`text-[10px] w-16 ${conf.color.split(" ")[1]}`}>{conf.label}</span>
              <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${(count / maxVal) * 100}%`,
                    background:
                      severity === "critical"
                        ? "linear-gradient(to right, rgba(239,68,68,0.6), rgba(239,68,68,0.3))"
                        : severity === "high"
                          ? "linear-gradient(to right, rgba(249,115,22,0.6), rgba(249,115,22,0.3))"
                          : severity === "medium"
                            ? "linear-gradient(to right, rgba(234,179,8,0.6), rgba(234,179,8,0.3))"
                            : severity === "low"
                              ? "linear-gradient(to right, rgba(16,185,129,0.6), rgba(16,185,129,0.3))"
                              : "linear-gradient(to right, rgba(100,116,139,0.6), rgba(100,116,139,0.3))",
                  }}
                />
              </div>
              <span className="text-[10px] font-mono text-muted-foreground w-8 text-right">{count}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

export default function BrowserDefensePage() {
  const [activeTab, setActiveTab] = useState<TabId>("sessions");
  const [searchQuery, setSearchQuery] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const {
    data: stats,
    isLoading: statsLoading,
    error: statsError,
  } = useQuery<BrowserDefenseStats>({
    queryKey: ["/api/browser-defense/stats"],
    queryFn: () =>
      apiQuery("/api/browser-defense/stats", (value): value is BrowserDefenseStats =>
        hasObjectKeys(value, ["totalSessions", "activeSessions", "totalEgressRules", "totalTrustedPaths"]),
      ),
  });

  const {
    data: sessions,
    isLoading: sessionsLoading,
    error: sessionsError,
  } = useQuery<BrowserSession[]>({
    queryKey: ["/api/browser-defense/sessions"],
    queryFn: () =>
      apiQuery("/api/browser-defense/sessions", (value): value is BrowserSession[] =>
        isArrayOf(value, (session) =>
          hasObjectKeys(session, [
            "id",
            "agentName",
            "contextId",
            "originUrl",
            "state",
            "isolationLevel",
            "lastActivityAt",
          ]),
        ),
      ),
  });

  const {
    data: domEvents,
    isLoading: eventsLoading,
    error: eventsError,
  } = useQuery<DomEvent[]>({
    queryKey: ["/api/browser-defense/dom-events"],
    queryFn: () =>
      apiQuery("/api/browser-defense/dom-events", (value): value is DomEvent[] =>
        isArrayOf(value, (event) =>
          hasObjectKeys(event, [
            "id",
            "sessionId",
            "eventType",
            "targetSelector",
            "actionClassification",
            "severity",
            "verdict",
          ]),
        ),
      ),
  });

  const {
    data: egressRules,
    isLoading: egressLoading,
    error: egressError,
  } = useQuery<EgressRule[]>({
    queryKey: ["/api/browser-defense/egress-rules"],
    queryFn: () =>
      apiQuery("/api/browser-defense/egress-rules", (value): value is EgressRule[] =>
        isArrayOf(value, (rule) =>
          hasObjectKeys(rule, [
            "id",
            "name",
            "description",
            "direction",
            "domainPattern",
            "action",
            "enabled",
            "hitCount",
          ]),
        ),
      ),
  });

  const {
    data: trustedPaths,
    isLoading: pathsLoading,
    error: pathsError,
  } = useQuery<TrustedPath[]>({
    queryKey: ["/api/browser-defense/trusted-paths"],
    queryFn: () =>
      apiQuery("/api/browser-defense/trusted-paths", (value): value is TrustedPath[] =>
        isArrayOf(value, (path) =>
          hasObjectKeys(path, [
            "id",
            "name",
            "description",
            "steps",
            "enforceOrder",
            "maxDurationMs",
            "failAction",
            "enabled",
          ]),
        ),
      ),
  });

  const {
    data: injectionPatterns,
    isLoading: patternsLoading,
    error: patternsError,
  } = useQuery<InjectionPattern[]>({
    queryKey: ["/api/browser-defense/injection-patterns"],
    queryFn: () =>
      apiQuery("/api/browser-defense/injection-patterns", (value): value is InjectionPattern[] =>
        isArrayOf(value, (pattern) =>
          hasObjectKeys(pattern, ["id", "name", "category", "pattern", "severity", "action", "description", "enabled"]),
        ),
      ),
  });

  const isolateMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      const res = await apiRequest("POST", `/api/browser-defense/sessions/${sessionId}/isolate`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Session isolated", description: "Browser session moved to container isolation." });
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/stats"] });
    },
  });

  const terminateMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      const res = await apiRequest("POST", `/api/browser-defense/sessions/${sessionId}/terminate`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Session terminated", description: "Browser session has been killed." });
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/stats"] });
    },
  });

  const deleteEgressMutation = useMutation({
    mutationFn: async (ruleId: string) => {
      const res = await apiRequest("DELETE", `/api/browser-defense/egress-rules/${ruleId}`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Egress rule deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/egress-rules"] });
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/stats"] });
    },
  });

  const toggleEgressMutation = useMutation({
    mutationFn: async ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/browser-defense/egress-rules/${ruleId}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/egress-rules"] });
    },
  });

  const togglePatternMutation = useMutation({
    mutationFn: async ({ patternId, enabled }: { patternId: string; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/browser-defense/injection-patterns/${patternId}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/browser-defense/injection-patterns"] });
    },
  });

  if (statsError) return <ApiQueryError error={statsError} label="browser defense statistics" />;
  if (sessionsError) return <ApiQueryError error={sessionsError} label="browser sessions" />;
  if (eventsError) return <ApiQueryError error={eventsError} label="browser DOM events" />;
  if (egressError) return <ApiQueryError error={egressError} label="browser egress rules" />;
  if (pathsError) return <ApiQueryError error={pathsError} label="browser trusted paths" />;
  if (patternsError) return <ApiQueryError error={patternsError} label="browser injection patterns" />;

  const filteredSessions = (sessions || []).filter(
    (s) =>
      searchQuery === "" ||
      s.agentName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.originUrl.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredEvents = (domEvents || []).filter(
    (e) =>
      searchQuery === "" ||
      e.eventType.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.actionClassification.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.targetSelector.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredEgress = (egressRules || []).filter(
    (r) =>
      searchQuery === "" ||
      r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.domainPattern.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredPaths = (trustedPaths || []).filter(
    (p) => searchQuery === "" || p.name.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredPatterns = (injectionPatterns || []).filter(
    (p) =>
      searchQuery === "" ||
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.category.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const tabs: Array<{ id: TabId; label: string; icon: typeof Shield; count?: number }> = [
    { id: "sessions", label: "Sessions", icon: MonitorSmartphone, count: sessions?.length },
    { id: "events", label: "DOM Events", icon: Activity, count: domEvents?.length },
    { id: "egress", label: "Egress Rules", icon: Globe, count: egressRules?.length },
    { id: "paths", label: "Trusted Paths", icon: Route, count: trustedPaths?.length },
    { id: "patterns", label: "Injection Detection", icon: Crosshair, count: injectionPatterns?.length },
  ];

  return (
    <div className="min-h-screen p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldBan className="h-6 w-6 text-cyan-400" aria-hidden="true" />
            Agentic Browser Defense
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Runtime controls for browser-capable automation — injection detection, egress restrictions, trusted paths,
            session isolation
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="gap-1.5 border-white/10 hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/30"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["/api/browser-defense"] });
            toast({ title: "Refreshed", description: "All browser defense data reloaded." });
          }}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard
            label="Active Sessions"
            value={stats.activeSessions}
            icon={MonitorSmartphone}
            accent="bg-emerald-500/10"
          />
          <StatCard label="Total Sessions" value={stats.totalSessions} icon={MonitorSmartphone} />
          <StatCard label="Egress Rules" value={stats.totalEgressRules} icon={Route} accent="bg-amber-500/10" />
          <StatCard label="Trusted Paths" value={stats.totalTrustedPaths} icon={Lock} accent="bg-purple-500/10" />
        </div>
      ) : (
        <div className="text-center py-8 text-sm text-muted-foreground">No stats available</div>
      )}

      <Card className="border-white/5">
        <CardContent className="p-4 text-xs text-muted-foreground">
          Event severity and threat-category breakdowns are unavailable because the browser-defense statistics endpoint
          currently exposes aggregate session, rule, and path counts only.
        </CardContent>
      </Card>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-1 bg-white/5 rounded-lg p-1">
          {tabs.map((tab) => {
            const TabIcon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-cyan-500/20 text-cyan-400"
                    : "text-muted-foreground hover:text-foreground hover:bg-white/5"
                }`}
              >
                <TabIcon className="h-3.5 w-3.5" aria-hidden="true" />
                {tab.label}
                {tab.count !== undefined && (
                  <span className="text-[9px] bg-white/10 px-1.5 py-0 rounded-full">{tab.count}</span>
                )}
              </button>
            );
          })}
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search..."
            className="pl-8 h-8 text-xs bg-white/5 border-white/10"
          />
        </div>
      </div>

      {activeTab === "sessions" && (
        <div className="space-y-3">
          {sessionsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
          ) : filteredSessions.length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <MonitorSmartphone className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No browser sessions found</p>
                <p className="text-xs text-muted-foreground mt-1">Sessions will appear when browser agents connect</p>
              </CardContent>
            </Card>
          ) : (
            filteredSessions.map((session) => (
              <SessionCard
                key={session.id}
                session={session}
                onIsolate={() => isolateMutation.mutate(session.id)}
                onTerminate={() => terminateMutation.mutate(session.id)}
                isActing={isolateMutation.isPending || terminateMutation.isPending}
              />
            ))
          )}
        </div>
      )}

      {activeTab === "events" && (
        <Card className="glass-card border-white/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              DOM Event Stream
              <span className="text-[10px] text-muted-foreground font-normal">({filteredEvents.length} events)</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {eventsLoading ? (
              <div className="p-4 space-y-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 rounded-lg" />
                ))}
              </div>
            ) : filteredEvents.length === 0 ? (
              <div className="p-8 text-center">
                <Activity className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No DOM events recorded</p>
              </div>
            ) : (
              <div className="max-h-[600px] overflow-y-auto">
                {filteredEvents.map((evt) => (
                  <DomEventRow key={evt.id} evt={evt} />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "egress" && (
        <div className="space-y-3">
          {egressLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)
          ) : filteredEgress.length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <Globe className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No egress rules configured</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Add rules to control outbound network access from browser agents
                </p>
              </CardContent>
            </Card>
          ) : (
            filteredEgress.map((rule) => (
              <EgressRuleCard
                key={rule.id}
                rule={rule}
                onDelete={() => deleteEgressMutation.mutate(rule.id)}
                onToggle={() => toggleEgressMutation.mutate({ ruleId: rule.id, enabled: !rule.enabled })}
                isDeleting={deleteEgressMutation.isPending}
              />
            ))
          )}
        </div>
      )}

      {activeTab === "paths" && (
        <div className="space-y-3">
          {pathsLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)
          ) : filteredPaths.length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <Route className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No trusted paths defined</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Define execution paths to enforce ordered, verified automation flows
                </p>
              </CardContent>
            </Card>
          ) : (
            filteredPaths.map((path) => <TrustedPathCard key={path.id} path={path} />)
          )}
        </div>
      )}

      {activeTab === "patterns" && (
        <div className="space-y-3">
          {patternsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)
          ) : filteredPatterns.length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <Crosshair className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No injection patterns configured</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Detection patterns protect against DOM injection, prompt manipulation, and XSS
                </p>
              </CardContent>
            </Card>
          ) : (
            filteredPatterns.map((pattern) => (
              <InjectionPatternCard
                key={pattern.id}
                pattern={pattern}
                onToggle={() => togglePatternMutation.mutate({ patternId: pattern.id, enabled: !pattern.enabled })}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}
