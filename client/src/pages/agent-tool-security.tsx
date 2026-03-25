import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldBan,
  Bot,
  Key,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  Eye,
  EyeOff,
  Fingerprint,
  Globe,
  Zap,
  Link2,
  ArrowRight,
  Clock,
  BarChart3,
  Activity,
  FileWarning,
  Terminal,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Layers,
  Settings,
  Trash2,
  Ban,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

interface ToolManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  publisher: string;
  scopes: string[];
  trustBoundary: string;
  riskLevel: string;
  allowedDestinations: string[];
  maxInvocationsPerMinute: number;
  maxInvocationsPerHour: number;
  requiresApproval: boolean;
  signatureHash: string;
  signedAt: string;
  signedBy: string;
  verified: boolean;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface ToolInvocation {
  id: string;
  orgId: string;
  agentId: string;
  agentName: string;
  toolId: string;
  toolName: string;
  toolVersion: string;
  scopes: string[];
  trustBoundary: string;
  destination: string | null;
  inputHash: string;
  outputHash: string | null;
  verdict: string;
  verdictReason: string;
  attestationPassed: boolean;
  riskScore: number;
  durationMs: number;
  chainId: string | null;
  chainPosition: number;
  parentInvocationId: string | null;
  invokedAt: string;
}

interface AnomalyDetection {
  id: string;
  orgId: string;
  type: string;
  severity: string;
  agentId: string;
  agentName: string;
  toolId: string;
  toolName: string;
  description: string;
  evidence: string;
  chainId: string | null;
  acknowledged: boolean;
  detectedAt: string;
}

interface ToolPolicy {
  id: string;
  orgId: string;
  toolId: string;
  toolName: string;
  maxRate: number;
  ratePeriod: string;
  allowedScopes: string[];
  blockedDestinations: string[];
  requireAttestation: boolean;
  autoApproveBelow: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface TrustBoundaryRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  sourceBoundary: string;
  targetBoundary: string;
  action: string;
  conditions: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface AgentToolStats {
  totalTools: number;
  verifiedTools: number;
  unverifiedTools: number;
  totalInvocations: number;
  allowedCount: number;
  deniedCount: number;
  throttledCount: number;
  flaggedCount: number;
  totalAnomalies: number;
  unresolvedAnomalies: number;
  activePolicies: number;
  boundaryRules: number;
  avgRiskScore: number;
  invocationsByTool: Record<string, { total: number; allowed: number; denied: number }>;
  anomaliesByType: Record<string, number>;
}

const RISK_CONFIG: Record<string, { label: string; color: string }> = {
  low: { label: "Low", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  medium: { label: "Medium", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  high: { label: "High", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  critical: { label: "Critical", color: "bg-red-500/20 text-red-400 border-red-500/30" },
};

const BOUNDARY_CONFIG: Record<string, { label: string; icon: typeof Shield; color: string }> = {
  internal: { label: "Internal", icon: Lock, color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  external: { label: "External", icon: Globe, color: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  privileged: { label: "Privileged", icon: Key, color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  sandboxed: { label: "Sandboxed", icon: ShieldBan, color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
};

const VERDICT_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  allowed: { label: "Allowed", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
  denied: { label: "Denied", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: XCircle },
  throttled: { label: "Throttled", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", icon: Clock },
  flagged: { label: "Flagged", color: "bg-orange-500/20 text-orange-400 border-orange-500/30", icon: AlertTriangle },
};

const ANOMALY_TYPE_CONFIG: Record<string, { label: string; icon: typeof Shield }> = {
  unusual_chaining: { label: "Unusual Chaining", icon: Link2 },
  scope_escalation: { label: "Scope Escalation", icon: Key },
  rate_spike: { label: "Rate Spike", icon: Zap },
  destination_drift: { label: "Destination Drift", icon: Globe },
  payload_anomaly: { label: "Payload Anomaly", icon: FileWarning },
};

const ACTION_CONFIG: Record<string, { label: string; color: string }> = {
  allow: { label: "Allow", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  deny: { label: "Deny", color: "bg-red-500/20 text-red-400 border-red-500/30" },
  require_approval: { label: "Require Approval", color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
};

type TabId = "manifests" | "invocations" | "anomalies" | "policies" | "boundaries";

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

function ToolManifestCard({
  tool,
  isExpanded,
  onToggle,
  onVerify,
  isVerifying,
}: {
  tool: ToolManifest;
  isExpanded: boolean;
  onToggle: () => void;
  onVerify: () => void;
  isVerifying: boolean;
}) {
  const riskConf = RISK_CONFIG[tool.riskLevel] || RISK_CONFIG.medium;
  const boundaryConf = BOUNDARY_CONFIG[tool.trustBoundary] || BOUNDARY_CONFIG.internal;
  const BoundaryIcon = boundaryConf.icon;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={onToggle}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <Terminal className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{tool.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${riskConf.color}`}>
                  {riskConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${boundaryConf.color}`}>
                  <BoundaryIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {boundaryConf.label}
                </Badge>
                {tool.verified ? (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  >
                    <ShieldCheck className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                    Verified
                  </Badge>
                ) : (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-red-500/20 text-red-400 border-red-500/30"
                  >
                    <ShieldAlert className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                    Unverified
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{tool.description}</p>
              <div className="flex items-center gap-2 mt-2 flex-wrap">
                <span className="text-[10px] text-muted-foreground">v{tool.version}</span>
                <span className="text-[10px] text-muted-foreground">Publisher: {tool.publisher}</span>
                <span className="text-[10px] text-muted-foreground">
                  Rate: {tool.maxInvocationsPerMinute}/min, {tool.maxInvocationsPerHour}/hr
                </span>
                {tool.requiresApproval && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-amber-500/10 text-amber-400/70 border-amber-500/10"
                  >
                    Approval Required
                  </Badge>
                )}
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
                onVerify();
              }}
              disabled={isVerifying}
              aria-label={`Verify tool: ${tool.name}`}
            >
              {isVerifying ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Fingerprint className="h-3 w-3" />}
              <span className="ml-1">Verify</span>
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
        <div className="px-4 pb-4 pt-1 border-t border-white/5 space-y-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
              Scopes ({tool.scopes.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {tool.scopes.map((scope) => (
                <Badge
                  key={scope}
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/5 text-cyan-400/70 border-cyan-500/10"
                >
                  {scope}
                </Badge>
              ))}
            </div>
          </div>
          {tool.allowedDestinations.length > 0 && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Allowed Destinations</p>
              <div className="flex flex-wrap gap-1">
                {tool.allowedDestinations.map((dest) => (
                  <Badge
                    key={dest}
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/5 text-purple-400/70 border-purple-500/10"
                  >
                    {dest}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-muted-foreground">Signature:</span>{" "}
              <code className="text-[9px] bg-white/5 px-1 py-0.5 rounded">{tool.signatureHash.slice(0, 24)}...</code>
            </div>
            <div>
              <span className="text-muted-foreground">Signed by:</span> {tool.signedBy}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function InvocationRow({ inv }: { inv: ToolInvocation }) {
  const [expanded, setExpanded] = useState(false);
  const verdictConf = VERDICT_CONFIG[inv.verdict] || VERDICT_CONFIG.allowed;
  const VerdictIcon = verdictConf.icon;
  const boundaryConf = BOUNDARY_CONFIG[inv.trustBoundary] || BOUNDARY_CONFIG.internal;

  return (
    <div className="border-b border-white/5 last:border-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left px-4 py-3 hover:bg-white/[0.02] transition-colors focus:outline-none focus:ring-1 focus:ring-cyan-500/30"
      >
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <VerdictIcon className={`h-4 w-4 shrink-0 ${verdictConf.color.split(" ")[1]}`} aria-hidden="true" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-medium truncate">{inv.toolName}</span>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  {verdictConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${boundaryConf.color}`}>
                  {boundaryConf.label}
                </Badge>
                {inv.attestationPassed ? (
                  <ShieldCheck className="h-3 w-3 text-emerald-400" aria-label="Attestation passed" />
                ) : (
                  <ShieldAlert className="h-3 w-3 text-red-400" aria-label="Attestation failed" />
                )}
              </div>
              <p className="text-[10px] text-muted-foreground mt-0.5">
                Agent: {inv.agentName} | Risk: {inv.riskScore} | {inv.durationMs}ms
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[10px] text-muted-foreground">{new Date(inv.invokedAt).toLocaleString()}</span>
            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          </div>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-3 space-y-2 text-xs">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="text-muted-foreground">Verdict Reason:</span> {inv.verdictReason}
            </div>
            <div>
              <span className="text-muted-foreground">Input Hash:</span>{" "}
              <code className="text-[9px] bg-white/5 px-1 py-0.5 rounded">{inv.inputHash}</code>
            </div>
            {inv.outputHash && (
              <div>
                <span className="text-muted-foreground">Output Hash:</span>{" "}
                <code className="text-[9px] bg-white/5 px-1 py-0.5 rounded">{inv.outputHash}</code>
              </div>
            )}
            {inv.destination && (
              <div>
                <span className="text-muted-foreground">Destination:</span> {inv.destination}
              </div>
            )}
            {inv.chainId && (
              <div>
                <span className="text-muted-foreground">Chain:</span> {inv.chainId} (pos {inv.chainPosition})
              </div>
            )}
          </div>
          <div>
            <span className="text-muted-foreground">Scopes:</span>{" "}
            {inv.scopes.map((s) => (
              <Badge
                key={s}
                variant="outline"
                className="text-[9px] px-1 py-0 h-3.5 mr-1 bg-cyan-500/5 text-cyan-400/70 border-cyan-500/10"
              >
                {s}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function AnomalyCard({
  anomaly,
  onAcknowledge,
  isAcknowledging,
}: {
  anomaly: AnomalyDetection;
  onAcknowledge: () => void;
  isAcknowledging: boolean;
}) {
  const typeConf = ANOMALY_TYPE_CONFIG[anomaly.type] || { label: anomaly.type, icon: AlertTriangle };
  const TypeIcon = typeConf.icon;
  const sevConf = RISK_CONFIG[anomaly.severity] || RISK_CONFIG.medium;

  return (
    <Card className={`glass-card border-white/5 ${!anomaly.acknowledged ? "border-l-2 border-l-orange-500/50" : ""}`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-orange-500/10 mt-0.5">
              <TypeIcon className="h-4 w-4 text-orange-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                  {sevConf.label}
                </Badge>
                <Badge
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-white/5 text-white/60 border-white/10"
                >
                  {typeConf.label}
                </Badge>
                {anomaly.acknowledged ? (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  >
                    <Eye className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                    Acknowledged
                  </Badge>
                ) : (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-red-500/20 text-red-400 border-red-500/30"
                  >
                    <EyeOff className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                    Unresolved
                  </Badge>
                )}
              </div>
              <p className="text-xs mt-1">{anomaly.description}</p>
              <p className="text-[10px] text-muted-foreground mt-1">
                Agent: {anomaly.agentName} | Tool: {anomaly.toolName}
              </p>
              <div className="mt-2 p-2 rounded bg-white/[0.03] border border-white/5">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Evidence</p>
                <p className="text-[11px] font-mono">{anomaly.evidence}</p>
              </div>
              <p className="text-[10px] text-muted-foreground mt-2">
                Detected: {new Date(anomaly.detectedAt).toLocaleString()}
                {anomaly.chainId && <> | Chain: {anomaly.chainId}</>}
              </p>
            </div>
          </div>
          {!anomaly.acknowledged && (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors shrink-0"
              onClick={onAcknowledge}
              disabled={isAcknowledging}
              aria-label="Acknowledge anomaly"
            >
              <SuccessIcon size={12} color="#22c55e" />
              Ack
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function PolicyCard({ policy }: { policy: ToolPolicy }) {
  return (
    <Card className="glass-card border-white/5">
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10">
              <Settings className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div>
              <h3 className="text-sm font-semibold">{policy.toolName}</h3>
              <p className="text-[10px] text-muted-foreground">
                Rate: {policy.maxRate}/{policy.ratePeriod} | Scopes: {policy.allowedScopes.length} | Blocked
                destinations: {policy.blockedDestinations.length}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {policy.requireAttestation && (
              <Badge
                variant="outline"
                className="text-[9px] px-1.5 py-0 h-4 bg-amber-500/20 text-amber-400 border-amber-500/30"
              >
                <Fingerprint className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                Attestation
              </Badge>
            )}
            <Badge
              variant="outline"
              className={`text-[9px] px-1.5 py-0 h-4 ${policy.enabled ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-zinc-500/20 text-zinc-400 border-zinc-500/30"}`}
            >
              {policy.enabled ? "Active" : "Disabled"}
            </Badge>
          </div>
        </div>
        <div className="mt-2 flex flex-wrap gap-1">
          {policy.allowedScopes.slice(0, 5).map((scope) => (
            <Badge
              key={scope}
              variant="outline"
              className="text-[9px] px-1 py-0 h-3.5 bg-cyan-500/5 text-cyan-400/70 border-cyan-500/10"
            >
              {scope}
            </Badge>
          ))}
          {policy.allowedScopes.length > 5 && (
            <span className="text-[9px] text-muted-foreground">+{policy.allowedScopes.length - 5} more</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function BoundaryRuleCard({
  rule,
  onDelete,
  isDeleting,
}: {
  rule: TrustBoundaryRule;
  onDelete: () => void;
  isDeleting: boolean;
}) {
  const srcConf = BOUNDARY_CONFIG[rule.sourceBoundary] || BOUNDARY_CONFIG.internal;
  const tgtConf = BOUNDARY_CONFIG[rule.targetBoundary] || BOUNDARY_CONFIG.internal;
  const actConf = ACTION_CONFIG[rule.action] || ACTION_CONFIG.deny;
  const SrcIcon = srcConf.icon;
  const TgtIcon = tgtConf.icon;

  return (
    <Card className="glass-card border-white/5">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold">{rule.name}</h3>
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${actConf.color}`}>
                {actConf.label}
              </Badge>
              <Badge
                variant="outline"
                className={`text-[9px] px-1.5 py-0 h-4 ${rule.enabled ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-zinc-500/20 text-zinc-400 border-zinc-500/30"}`}
              >
                {rule.enabled ? "Active" : "Disabled"}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-1">{rule.description}</p>
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${srcConf.color}`}>
                <SrcIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                {srcConf.label}
              </Badge>
              <ArrowRight className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${tgtConf.color}`}>
                <TgtIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                {tgtConf.label}
              </Badge>
            </div>
            {rule.conditions.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {rule.conditions.map((cond, idx) => (
                  <Badge
                    key={idx}
                    variant="outline"
                    className="text-[9px] px-1 py-0 h-3.5 bg-white/5 text-white/50 border-white/10"
                  >
                    {cond}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-[10px] hover:bg-red-500/10 hover:text-red-400 transition-colors shrink-0"
            onClick={onDelete}
            disabled={isDeleting}
            aria-label={`Delete rule: ${rule.name}`}
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function InvocationByToolChart({ data }: { data: Record<string, { total: number; allowed: number; denied: number }> }) {
  const entries = Object.entries(data).sort((a, b) => b[1].total - a[1].total);
  if (entries.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Invocations by Tool
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-4">
          <p className="text-xs text-muted-foreground">No invocation data yet.</p>
        </CardContent>
      </Card>
    );
  }
  const maxTotal = Math.max(...entries.map(([, v]) => v.total));
  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          Invocations by Tool
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4 space-y-2">
        {entries.slice(0, 8).map(([name, d]) => (
          <div key={name} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="truncate max-w-[180px]">{name}</span>
              <div className="flex items-center gap-2">
                <span className="text-emerald-400">{d.allowed}A</span>
                <span className="text-red-400">{d.denied}D</span>
                <span className="text-muted-foreground">{d.total}</span>
              </div>
            </div>
            <div
              className="h-1.5 bg-white/5 rounded-full overflow-hidden"
              role="progressbar"
              aria-valuenow={d.total}
              aria-valuemin={0}
              aria-valuemax={maxTotal}
              aria-label={`${name} invocations`}
            >
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all duration-500"
                style={{ width: `${maxTotal > 0 ? (d.total / maxTotal) * 100 : 0}%` }}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function AnomalyByTypeChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return (
      <Card className="glass-card border-white/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" aria-hidden="true" />
            Anomalies by Type
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-4">
          <p className="text-xs text-muted-foreground">No anomalies detected yet.</p>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card className="glass-card border-white/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-orange-400" aria-hidden="true" />
          Anomalies by Type
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4 space-y-2">
        {entries.map(([type, count]) => {
          const conf = ANOMALY_TYPE_CONFIG[type] || { label: type, icon: AlertTriangle };
          const TypeIcon = conf.icon;
          return (
            <div
              key={type}
              className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0"
            >
              <div className="flex items-center gap-1.5">
                <TypeIcon className="h-3 w-3 text-orange-400" aria-hidden="true" />
                <span>{conf.label}</span>
              </div>
              <span className="text-orange-400 font-medium">{count}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

export default function AgentToolSecurityPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabId>("manifests");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedTools, setExpandedTools] = useState<Set<string>>(new Set());
  const [verdictFilter, setVerdictFilter] = useState<string>("all");

  const { data: stats, isLoading: statsLoading } = useQuery<AgentToolStats>({
    queryKey: ["/api/agent-tool-security/stats"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/agent-tool-security/stats");
      return res.json();
    },
  });

  const { data: tools, isLoading: toolsLoading } = useQuery<ToolManifest[]>({
    queryKey: ["/api/agent-tool-security/tools"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/agent-tool-security/tools");
      return res.json();
    },
  });

  const { data: invocations, isLoading: invocationsLoading } = useQuery<ToolInvocation[]>({
    queryKey: ["/api/agent-tool-security/invocations"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/agent-tool-security/invocations");
      return res.json();
    },
  });

  const { data: anomalies, isLoading: anomaliesLoading } = useQuery<AnomalyDetection[]>({
    queryKey: ["/api/agent-tool-security/anomalies"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/agent-tool-security/anomalies");
      return res.json();
    },
  });

  const { data: policies, isLoading: policiesLoading } = useQuery<ToolPolicy[]>({
    queryKey: ["/api/agent-tool-security/policies"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/agent-tool-security/policies");
      return res.json();
    },
  });

  const { data: boundaryRules, isLoading: boundaryRulesLoading } = useQuery<TrustBoundaryRule[]>({
    queryKey: ["/api/agent-tool-security/boundary-rules"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/agent-tool-security/boundary-rules");
      return res.json();
    },
  });

  const verifyToolMutation = useMutation({
    mutationFn: async (toolId: string) => {
      const res = await apiRequest("POST", `/api/agent-tool-security/tools/${toolId}/verify`);
      return res.json();
    },
    onSuccess: (data: { verified: boolean; reason: string }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/agent-tool-security/tools"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agent-tool-security/stats"] });
      toast({
        title: data.verified ? "Attestation Passed" : "Attestation Failed",
        description: data.reason,
      });
    },
  });

  const acknowledgeMutation = useMutation({
    mutationFn: async (anomalyId: string) => {
      const res = await apiRequest("POST", `/api/agent-tool-security/anomalies/${anomalyId}/acknowledge`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/agent-tool-security/anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agent-tool-security/stats"] });
      toast({ title: "Anomaly acknowledged" });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: async (ruleId: string) => {
      const res = await apiRequest("DELETE", `/api/agent-tool-security/boundary-rules/${ruleId}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/agent-tool-security/boundary-rules"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agent-tool-security/stats"] });
      toast({ title: "Boundary rule deleted" });
    },
  });

  const toggleToolExpand = (id: string) => {
    setExpandedTools((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredTools = (tools || []).filter(
    (t) =>
      !searchQuery ||
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.scopes.some((s) => s.toLowerCase().includes(searchQuery.toLowerCase())),
  );

  const filteredInvocations = (invocations || []).filter((inv) => {
    if (verdictFilter !== "all" && inv.verdict !== verdictFilter) return false;
    if (
      searchQuery &&
      !inv.toolName.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !inv.agentName.toLowerCase().includes(searchQuery.toLowerCase())
    )
      return false;
    return true;
  });

  const filteredAnomalies = (anomalies || []).filter(
    (a) =>
      !searchQuery ||
      a.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.toolName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.agentName.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const tabs: { id: TabId; label: string; icon: typeof Shield; count?: number }[] = [
    { id: "manifests", label: "Tool Manifests", icon: Terminal, count: tools?.length },
    { id: "invocations", label: "Invocation Trace", icon: Activity, count: invocations?.length },
    { id: "anomalies", label: "Anomalies", icon: AlertTriangle, count: stats?.unresolvedAnomalies },
    { id: "policies", label: "Policies", icon: Settings, count: stats?.activePolicies },
    { id: "boundaries", label: "Trust Boundaries", icon: Layers, count: boundaryRules?.length },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-cyan-400" aria-hidden="true" />
            Agent/Tool Interaction Security
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Signed manifests, least-privilege scopes, trust boundaries, anomaly detection, forensic replay
          </p>
        </div>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard label="Total Tools" value={stats.totalTools} icon={Terminal} />
          <StatCard label="Verified" value={stats.verifiedTools} icon={ShieldCheck} accent="bg-emerald-500/10" />
          <StatCard label="Invocations" value={stats.totalInvocations} icon={Activity} />
          <StatCard label="Denied" value={stats.deniedCount} icon={Ban} accent="bg-red-500/10" />
          <StatCard
            label="Anomalies"
            value={stats.unresolvedAnomalies}
            icon={AlertTriangle}
            accent="bg-orange-500/10"
          />
          <StatCard label="Avg Risk" value={stats.avgRiskScore} icon={BarChart3} />
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {stats && <InvocationByToolChart data={stats.invocationsByTool} />}
        {stats && <AnomalyByTypeChart data={stats.anomaliesByType} />}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder="Search tools, agents, anomalies..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 h-8 text-xs bg-white/5 border-white/10"
            aria-label="Search"
          />
        </div>
        {activeTab === "invocations" && (
          <div className="flex gap-1">
            {["all", "allowed", "denied", "throttled", "flagged"].map((v) => (
              <Button
                key={v}
                size="sm"
                variant={verdictFilter === v ? "default" : "ghost"}
                className="h-7 px-2 text-[10px]"
                onClick={() => setVerdictFilter(v)}
              >
                {v === "all" ? "All" : VERDICT_CONFIG[v]?.label || v}
              </Button>
            ))}
          </div>
        )}
      </div>

      <div className="flex gap-1 border-b border-white/10 pb-1" role="tablist">
        {tabs.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={activeTab === tab.id}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-t transition-colors ${
                activeTab === tab.id
                  ? "bg-cyan-500/10 text-cyan-400 border-b-2 border-cyan-400"
                  : "text-muted-foreground hover:text-foreground hover:bg-white/5"
              }`}
              onClick={() => setActiveTab(tab.id)}
            >
              <TabIcon className="h-3.5 w-3.5" aria-hidden="true" />
              {tab.label}
              {tab.count !== undefined && (
                <span className="ml-1 text-[9px] bg-white/10 px-1.5 py-0 rounded-full">{tab.count}</span>
              )}
            </button>
          );
        })}
      </div>

      {activeTab === "manifests" && (
        <div className="space-y-3">
          {toolsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)
          ) : filteredTools.length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <Terminal className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">No tool manifests found.</p>
              </CardContent>
            </Card>
          ) : (
            filteredTools.map((tool) => (
              <ToolManifestCard
                key={tool.id}
                tool={tool}
                isExpanded={expandedTools.has(tool.id)}
                onToggle={() => toggleToolExpand(tool.id)}
                onVerify={() => verifyToolMutation.mutate(tool.id)}
                isVerifying={verifyToolMutation.isPending}
              />
            ))
          )}
        </div>
      )}

      {activeTab === "invocations" && (
        <Card className="glass-card border-white/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" aria-hidden="true" />
              Invocation Trace Log
              <span className="text-[10px] text-muted-foreground font-normal ml-2">
                {filteredInvocations.length} records
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {invocationsLoading ? (
              <div className="p-4 space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-14" />
                ))}
              </div>
            ) : filteredInvocations.length === 0 ? (
              <div className="p-8 text-center">
                <Activity className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">No invocations found matching filters.</p>
              </div>
            ) : (
              filteredInvocations.slice(0, 50).map((inv) => <InvocationRow key={inv.id} inv={inv} />)
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "anomalies" && (
        <div className="space-y-3">
          {anomaliesLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-32" />)
          ) : filteredAnomalies.length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <AlertTriangle className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">No anomalies detected.</p>
              </CardContent>
            </Card>
          ) : (
            filteredAnomalies.map((anomaly) => (
              <AnomalyCard
                key={anomaly.id}
                anomaly={anomaly}
                onAcknowledge={() => acknowledgeMutation.mutate(anomaly.id)}
                isAcknowledging={acknowledgeMutation.isPending}
              />
            ))
          )}
        </div>
      )}

      {activeTab === "policies" && (
        <div className="space-y-3">
          {policiesLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20" />)
          ) : (policies || []).length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <Settings className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">No tool policies configured.</p>
              </CardContent>
            </Card>
          ) : (
            (policies || []).map((policy) => <PolicyCard key={policy.id} policy={policy} />)
          )}
        </div>
      )}

      {activeTab === "boundaries" && (
        <div className="space-y-3">
          {boundaryRulesLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24" />)
          ) : (boundaryRules || []).length === 0 ? (
            <Card className="glass-card border-white/5">
              <CardContent className="p-8 text-center">
                <Layers className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">No trust boundary rules configured.</p>
              </CardContent>
            </Card>
          ) : (
            (boundaryRules || []).map((rule) => (
              <BoundaryRuleCard
                key={rule.id}
                rule={rule}
                onDelete={() => deleteRuleMutation.mutate(rule.id)}
                isDeleting={deleteRuleMutation.isPending}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}
