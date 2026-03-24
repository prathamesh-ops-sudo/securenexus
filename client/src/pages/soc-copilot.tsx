import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import {
  Brain,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  Target,
  Zap,
  Eye,
  ThumbsUp,
  ThumbsDown,
  RotateCcw,
  ChevronDown,
  ChevronRight,
  Activity,
  GitBranch,
  Lightbulb,
  Play,
  Ban,
  BarChart3,
  MessageSquare,
  TrendingUp,
  ArrowRight,
  Crosshair,
  FileText,
  Network,
  Server,
  Globe,
  User,
  Wrench,
  Microscope,
  Bug,
  Cloud,
  Send,
  Sparkles,
  PanelRight,
  History,
  Loader2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

interface TriageSummary {
  id: string;
  orgId: string;
  alertId: string;
  alertTitle: string;
  severity: string;
  verdict: string;
  confidence: number;
  summary: string;
  keyIndicators: string[];
  recommendedActions: string[];
  relatedAlertIds: string[];
  analystNotes: string;
  createdAt: string;
  updatedAt: string;
}

interface TimelineEntry {
  timestamp: string;
  source: string;
  eventType: string;
  description: string;
  severity: string;
  entityId: string | null;
  entityType: string | null;
  rawRef: string | null;
}

interface CorrelatedTimeline {
  id: string;
  orgId: string;
  incidentId: string;
  incidentTitle: string;
  entries: TimelineEntry[];
  generatedAt: string;
  scope: string;
  totalDurationMs: number;
}

interface IncidentHypothesis {
  id: string;
  orgId: string;
  incidentId: string;
  incidentTitle: string;
  hypothesis: string;
  confidence: string;
  confidenceScore: number;
  supportingEvidence: string[];
  attackTechniques: string[];
  suggestedInvestigationSteps: string[];
  status: string;
  analystFeedback: string | null;
  createdAt: string;
  updatedAt: string;
}

interface AutonomousAction {
  id: string;
  orgId: string;
  actionClass: string;
  name: string;
  description: string;
  targetEntity: string;
  targetEntityType: string;
  confidenceScore: number;
  confidenceThreshold: number;
  status: string;
  rollbackPlan: string;
  rollbackExecuted: boolean;
  executionResult: string | null;
  triggeredBy: string;
  approvedBy: string | null;
  rejectedBy: string | null;
  executedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface FeedbackRecord {
  id: string;
  orgId: string;
  actionId: string;
  actionType: string;
  outcome: string;
  analystId: string;
  originalSuggestion: string;
  analystOverride: string | null;
  reason: string;
  impactOnPolicy: string | null;
  createdAt: string;
}

interface PolicyCalibration {
  id: string;
  orgId: string;
  domain: string;
  policyName: string;
  previousThreshold: number;
  newThreshold: number;
  triggerReason: string;
  feedbackCount: number;
  acceptanceRate: number;
  overrideRate: number;
  calibratedAt: string;
}

interface CopilotStats {
  totalTriages: number;
  totalTimelines: number;
  totalHypotheses: number;
  totalActions: number;
  autoExecutedActions: number;
  pendingApprovals: number;
  feedbackCount: number;
  acceptanceRate: number;
  overrideRate: number;
  avgConfidence: number;
  byDomain: Record<string, { total: number; accepted: number; overridden: number }>;
  byActionClass: Record<string, { total: number; executed: number; rejected: number }>;
  recentCalibrations: number;
}

const SEVERITY_CONFIG: Record<string, { label: string; color: string }> = {
  info: { label: "Info", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
  low: { label: "Low", color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  medium: { label: "Medium", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  high: { label: "High", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  critical: { label: "Critical", color: "bg-red-500/20 text-red-400 border-red-500/30" },
};

const VERDICT_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  true_positive: { label: "True Positive", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: ShieldAlert },
  false_positive: {
    label: "False Positive",
    color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    icon: ShieldCheck,
  },
  needs_investigation: {
    label: "Needs Investigation",
    color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    icon: Search,
  },
  benign: { label: "Benign", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30", icon: CheckCircle2 },
};

const ACTION_CLASS_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  READ: { label: "READ", color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Eye },
  SUGGEST: { label: "SUGGEST", color: "bg-purple-500/20 text-purple-400 border-purple-500/30", icon: Lightbulb },
  EXECUTE_WITH_APPROVAL: {
    label: "EXECUTE w/ APPROVAL",
    color: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    icon: ShieldAlert,
  },
  AUTO_EXECUTE_LOW_RISK: {
    label: "AUTO-EXECUTE",
    color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    icon: Zap,
  },
};

const ACTION_STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  pending_approval: {
    label: "Pending Approval",
    color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    icon: Clock,
  },
  approved: {
    label: "Approved",
    color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    icon: CheckCircle2,
  },
  rejected: { label: "Rejected", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: XCircle },
  executed: { label: "Executed", color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30", icon: Play },
  rolled_back: {
    label: "Rolled Back",
    color: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    icon: RotateCcw,
  },
  auto_executed: {
    label: "Auto-Executed",
    color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    icon: Zap,
  },
};

const CONFIDENCE_CONFIG: Record<string, { label: string; color: string }> = {
  high: { label: "High", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  medium: { label: "Medium", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  low: { label: "Low", color: "bg-red-500/20 text-red-400 border-red-500/30" },
};

const FEEDBACK_OUTCOME_CONFIG: Record<string, { label: string; color: string }> = {
  accepted: { label: "Accepted", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  overridden: { label: "Overridden", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  dismissed: { label: "Dismissed", color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30" },
};

const ENTITY_TYPE_ICONS: Record<string, typeof Shield> = {
  ip: Globe,
  domain: Network,
  endpoint: Server,
  user: User,
  network: Network,
};

type TabId = "triage" | "timeline" | "hypotheses" | "actions" | "feedback";

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

function TriageCard({
  triage,
  isExpanded,
  onToggle,
}: {
  triage: TriageSummary;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const sevConf = SEVERITY_CONFIG[triage.severity] || SEVERITY_CONFIG.medium;
  const verdictConf = VERDICT_CONFIG[triage.verdict] || VERDICT_CONFIG.needs_investigation;
  const VerdictIcon = verdictConf.icon;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={onToggle}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
        aria-expanded={isExpanded}
        aria-label={`Triage: ${triage.alertTitle}`}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <VerdictIcon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold truncate">{triage.alertTitle}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                  {sevConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${verdictConf.color}`}>
                  {verdictConf.label}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Alert {triage.alertId} &middot; Confidence: {(triage.confidence * 100).toFixed(0)}%
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <span className="text-[10px] text-muted-foreground">{new Date(triage.createdAt).toLocaleDateString()}</span>
            {isExpanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </button>
      {isExpanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-white/5 pt-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Summary</p>
            <p className="text-xs leading-relaxed">{triage.summary}</p>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Key Indicators</p>
            <ul className="space-y-1">
              {triage.keyIndicators.map((indicator, i) => (
                <li key={i} className="text-xs flex items-start gap-1.5">
                  <ArrowRight className="h-3 w-3 text-cyan-400 mt-0.5 shrink-0" aria-hidden="true" />
                  {indicator}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Recommended Actions</p>
            <ul className="space-y-1">
              {triage.recommendedActions.map((action, i) => (
                <li key={i} className="text-xs flex items-start gap-1.5">
                  <Target className="h-3 w-3 text-amber-400 mt-0.5 shrink-0" aria-hidden="true" />
                  {action}
                </li>
              ))}
            </ul>
          </div>
          {triage.relatedAlertIds.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] text-muted-foreground">Related:</span>
              {triage.relatedAlertIds.map((id) => (
                <Badge
                  key={id}
                  variant="outline"
                  className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/5 text-cyan-400/70 border-cyan-500/10"
                >
                  {id}
                </Badge>
              ))}
            </div>
          )}
          <div
            className="h-1.5 bg-white/5 rounded-full overflow-hidden"
            role="progressbar"
            aria-valuenow={Math.round(triage.confidence * 100)}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Confidence score"
          >
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                triage.confidence >= 0.8
                  ? "bg-gradient-to-r from-emerald-500 to-cyan-500"
                  : triage.confidence >= 0.6
                    ? "bg-gradient-to-r from-yellow-500 to-amber-500"
                    : "bg-gradient-to-r from-red-500 to-orange-500"
              }`}
              style={{ width: `${triage.confidence * 100}%` }}
            />
          </div>
        </div>
      )}
    </Card>
  );
}

function TimelineCard({ timeline }: { timeline: CorrelatedTimeline }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const durationHours = (timeline.totalDurationMs / 3600000).toFixed(1);

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full text-left p-4 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded-lg"
        aria-expanded={isExpanded}
        aria-label={`Timeline: ${timeline.incidentTitle}`}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-cyan-500/10 mt-0.5">
              <GitBranch className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-semibold">{timeline.incidentTitle}</h3>
              <p className="text-xs text-muted-foreground mt-1">
                {timeline.incidentId} &middot; {timeline.entries.length} events &middot; {durationHours}h span
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">{timeline.scope}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            {isExpanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </button>
      {isExpanded && (
        <div className="px-4 pb-4 border-t border-white/5 pt-3">
          <div className="relative pl-6">
            <div className="absolute left-2 top-0 bottom-0 w-px bg-cyan-500/20" />
            {timeline.entries.map((entry, i) => {
              const sevConf = SEVERITY_CONFIG[entry.severity] || SEVERITY_CONFIG.medium;
              const EntityIcon = entry.entityType ? ENTITY_TYPE_ICONS[entry.entityType] || Activity : Activity;
              return (
                <div key={i} className="relative mb-4 last:mb-0">
                  <div
                    className={`absolute -left-4 top-1 w-3 h-3 rounded-full border-2 ${
                      entry.severity === "critical"
                        ? "bg-red-500 border-red-400"
                        : entry.severity === "high"
                          ? "bg-orange-500 border-orange-400"
                          : entry.severity === "medium"
                            ? "bg-yellow-500 border-yellow-400"
                            : "bg-blue-500 border-blue-400"
                    }`}
                  />
                  <div className="ml-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {new Date(entry.timestamp).toLocaleString()}
                      </span>
                      <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${sevConf.color}`}>
                        {sevConf.label}
                      </Badge>
                      <Badge
                        variant="outline"
                        className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                      >
                        {entry.source}
                      </Badge>
                    </div>
                    <p className="text-xs mt-1">{entry.description}</p>
                    {entry.entityId && (
                      <div className="flex items-center gap-1 mt-1">
                        <EntityIcon className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                        <span className="text-[10px] text-muted-foreground font-mono">{entry.entityId}</span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}

function HypothesisCard({
  hypothesis,
  onUpdateStatus,
  isUpdating,
}: {
  hypothesis: IncidentHypothesis;
  onUpdateStatus: (status: string) => void;
  isUpdating: boolean;
}) {
  const confConf = CONFIDENCE_CONFIG[hypothesis.confidence] || CONFIDENCE_CONFIG.medium;
  const [showDetails, setShowDetails] = useState(false);

  const statusColors: Record<string, string> = {
    active: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    confirmed: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    rejected: "bg-red-500/20 text-red-400 border-red-500/30",
    superseded: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  };

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="p-2 rounded-lg bg-purple-500/10 mt-0.5">
              <Lightbulb className="h-4 w-4 text-purple-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] text-muted-foreground">{hypothesis.incidentId}</span>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${confConf.color}`}>
                  {confConf.label} ({(hypothesis.confidenceScore * 100).toFixed(0)}%)
                </Badge>
                <Badge
                  variant="outline"
                  className={`text-[9px] px-1.5 py-0 h-4 ${statusColors[hypothesis.status] || statusColors.active}`}
                >
                  {hypothesis.status}
                </Badge>
              </div>
              <p className="text-xs mt-2 leading-relaxed">{hypothesis.hypothesis}</p>
            </div>
          </div>
        </div>

        <button
          onClick={() => setShowDetails(!showDetails)}
          className="mt-2 text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded px-1"
          aria-expanded={showDetails}
        >
          {showDetails ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          {showDetails ? "Hide details" : "Show evidence & techniques"}
        </button>

        {showDetails && (
          <div className="mt-3 space-y-3 border-t border-white/5 pt-3">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Supporting Evidence</p>
              <ul className="space-y-1">
                {hypothesis.supportingEvidence.map((ev, i) => (
                  <li key={i} className="text-xs flex items-start gap-1.5">
                    <CheckCircle2 className="h-3 w-3 text-emerald-400 mt-0.5 shrink-0" aria-hidden="true" />
                    {ev}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-1">
                {hypothesis.attackTechniques.map((tech) => (
                  <Badge
                    key={tech}
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-red-500/5 text-red-400/70 border-red-500/10"
                  >
                    {tech}
                  </Badge>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Investigation Steps</p>
              <ul className="space-y-1">
                {hypothesis.suggestedInvestigationSteps.map((step, i) => (
                  <li key={i} className="text-xs flex items-start gap-1.5">
                    <Crosshair className="h-3 w-3 text-cyan-400 mt-0.5 shrink-0" aria-hidden="true" />
                    {step}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {hypothesis.status === "active" && (
          <div className="mt-3 flex items-center gap-2 border-t border-white/5 pt-3">
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-emerald-500/10 hover:text-emerald-400"
              onClick={() => onUpdateStatus("confirmed")}
              disabled={isUpdating}
              aria-label="Confirm hypothesis"
            >
              <ThumbsUp className="h-3 w-3 mr-1" aria-hidden="true" />
              Confirm
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-red-500/10 hover:text-red-400"
              onClick={() => onUpdateStatus("rejected")}
              disabled={isUpdating}
              aria-label="Reject hypothesis"
            >
              <ThumbsDown className="h-3 w-3 mr-1" aria-hidden="true" />
              Reject
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-[10px] hover:bg-zinc-500/10 hover:text-zinc-400"
              onClick={() => onUpdateStatus("superseded")}
              disabled={isUpdating}
              aria-label="Mark hypothesis as superseded"
            >
              <Ban className="h-3 w-3 mr-1" aria-hidden="true" />
              Superseded
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

function ActionCard({
  action,
  onApprove,
  onReject,
  onRollback,
  isMutating,
}: {
  action: AutonomousAction;
  onApprove: () => void;
  onReject: () => void;
  onRollback: () => void;
  isMutating: boolean;
}) {
  const classConf = ACTION_CLASS_CONFIG[action.actionClass] || ACTION_CLASS_CONFIG.READ;
  const ClassIcon = classConf.icon;
  const statusConf = ACTION_STATUS_CONFIG[action.status] || ACTION_STATUS_CONFIG.pending_approval;
  const StatusIcon = statusConf.icon;
  const EntityIcon = ENTITY_TYPE_ICONS[action.targetEntityType] || Activity;
  const [showRollback, setShowRollback] = useState(false);

  const meetsThreshold = action.confidenceScore >= action.confidenceThreshold;

  return (
    <Card className="glass-card border-white/5 hover:border-cyan-500/20 transition-colors">
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div
              className={`p-2 rounded-lg ${action.actionClass === "AUTO_EXECUTE_LOW_RISK" ? "bg-emerald-500/10" : action.actionClass === "EXECUTE_WITH_APPROVAL" ? "bg-orange-500/10" : "bg-cyan-500/10"}`}
            >
              <ClassIcon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold">{action.name}</h3>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${classConf.color}`}>
                  {classConf.label}
                </Badge>
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${statusConf.color}`}>
                  <StatusIcon className="h-2.5 w-2.5 mr-0.5" aria-hidden="true" />
                  {statusConf.label}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1">{action.description}</p>
              <div className="flex items-center gap-3 mt-2 flex-wrap">
                <div className="flex items-center gap-1">
                  <EntityIcon className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                  <span className="text-[10px] text-muted-foreground font-mono">{action.targetEntity}</span>
                </div>
                <span className="text-[10px] text-muted-foreground">
                  Confidence: {(action.confidenceScore * 100).toFixed(0)}% / Threshold:{" "}
                  {(action.confidenceThreshold * 100).toFixed(0)}%
                </span>
                {!meetsThreshold && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1.5 py-0 h-4 bg-red-500/10 text-red-400 border-red-500/20"
                  >
                    Below threshold
                  </Badge>
                )}
              </div>
            </div>
          </div>
        </div>

        {action.executionResult && (
          <div className="mt-3 p-2 rounded-md bg-white/5">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Execution Result</p>
            <p className="text-xs font-mono">{action.executionResult}</p>
          </div>
        )}

        <button
          onClick={() => setShowRollback(!showRollback)}
          className="mt-2 text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 rounded px-1"
          aria-expanded={showRollback}
        >
          {showRollback ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          Rollback Plan
        </button>
        {showRollback && (
          <div className="mt-2 p-2 rounded-md bg-orange-500/5 border border-orange-500/10">
            <p className="text-xs">{action.rollbackPlan}</p>
            {action.rollbackExecuted && (
              <Badge
                variant="outline"
                className="text-[9px] px-1.5 py-0 h-4 bg-orange-500/20 text-orange-400 border-orange-500/30 mt-1"
              >
                Rollback Executed
              </Badge>
            )}
          </div>
        )}

        <div className="mt-3 flex items-center gap-2 border-t border-white/5 pt-3">
          {action.status === "pending_approval" && (
            <>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-[10px] hover:bg-emerald-500/10 hover:text-emerald-400"
                onClick={onApprove}
                disabled={isMutating}
                aria-label={`Approve action: ${action.name}`}
              >
                <ThumbsUp className="h-3 w-3 mr-1" aria-hidden="true" />
                Approve
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-[10px] hover:bg-red-500/10 hover:text-red-400"
                onClick={onReject}
                disabled={isMutating}
                aria-label={`Reject action: ${action.name}`}
              >
                <ThumbsDown className="h-3 w-3 mr-1" aria-hidden="true" />
                Reject
              </Button>
            </>
          )}
          {(action.status === "executed" || action.status === "approved" || action.status === "auto_executed") &&
            !action.rollbackExecuted && (
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-[10px] hover:bg-orange-500/10 hover:text-orange-400"
                onClick={onRollback}
                disabled={isMutating}
                aria-label={`Rollback action: ${action.name}`}
              >
                <RotateCcw className="h-3 w-3 mr-1" aria-hidden="true" />
                Rollback
              </Button>
            )}
          <span className="text-[10px] text-muted-foreground ml-auto">
            {action.triggeredBy}
            {action.approvedBy && ` / approved: ${action.approvedBy}`}
            {action.rejectedBy && ` / rejected: ${action.rejectedBy}`}
          </span>
        </div>
      </div>
    </Card>
  );
}

// ── 31.1 Context-Aware Suggestion Interface ──
interface ContextSuggestion {
  id: string;
  text: string;
  skill: string;
  icon: string;
}

// ── 31.5 Skill Definition Interface ──
interface CopilotSkill {
  id: string;
  name: string;
  description: string;
  icon: string;
  keywords: string[];
  category: string;
}

// ── 31.1 Context-Aware Quick Suggestions Component ──
function ContextAwareSuggestions({
  currentPage,
  onSelect,
}: {
  currentPage: string;
  onSelect: (suggestion: string) => void;
}) {
  const pageSuggestions: Record<string, { text: string; skill: string }[]> = {
    alerts: [
      { text: "Triage the latest critical alerts", skill: "incident_response" },
      { text: "Find IOCs in recent detections", skill: "threat_intel" },
      { text: "Generate SIGMA rules for these alerts", skill: "hunting" },
    ],
    incidents: [
      { text: "Summarize this incident timeline", skill: "incident_response" },
      { text: "Suggest containment actions", skill: "remediation" },
      { text: "Check for lateral movement indicators", skill: "hunting" },
    ],
    vulnerabilities: [
      { text: "Prioritize CVEs by exploitability", skill: "vulnerability_mgmt" },
      { text: "Generate a patch plan", skill: "remediation" },
      { text: "Check if any CVEs are actively exploited", skill: "threat_intel" },
    ],
    compliance: [
      { text: "Show SOC 2 control gaps", skill: "compliance" },
      { text: "Generate compliance evidence", skill: "compliance" },
      { text: "Compare against NIST framework", skill: "compliance" },
    ],
    default: [
      { text: "What are the top threats today?", skill: "threat_intel" },
      { text: "Show me recent incident trends", skill: "incident_response" },
      { text: "Run a quick security posture check", skill: "compliance" },
    ],
  };

  const suggestions = pageSuggestions[currentPage] || pageSuggestions.default;

  return (
    <div className="space-y-1.5">
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider flex items-center gap-1">
        <Sparkles className="h-3 w-3" />
        Suggested for this page
      </div>
      {suggestions.map((s, i) => (
        <button
          key={i}
          onClick={() => onSelect(s.text)}
          className="w-full text-left text-xs px-3 py-2 rounded-md bg-muted/30 hover:bg-muted/50 transition-colors flex items-center gap-2"
        >
          <ArrowRight className="h-3 w-3 text-primary/60 shrink-0" />
          <span>{s.text}</span>
          <Badge variant="outline" className="ml-auto text-[9px] shrink-0">
            {s.skill}
          </Badge>
        </button>
      ))}
    </div>
  );
}

// ── 31.2 Quick Action Buttons Component ──
function QuickActionButtons({ onAction }: { onAction: (action: string) => void }) {
  const actions = [
    { id: "summarize", label: "Summarize", icon: FileText },
    { id: "hunt", label: "Hunt", icon: Crosshair },
    { id: "remediate", label: "Remediate", icon: Wrench },
    { id: "enrich", label: "Enrich IOC", icon: Search },
    { id: "detect", label: "Detect", icon: Shield },
    { id: "comply", label: "Compliance", icon: CheckCircle2 },
  ];

  return (
    <div className="flex flex-wrap gap-1.5">
      {actions.map((a) => (
        <Button key={a.id} variant="outline" size="sm" className="h-7 text-[10px] gap-1" onClick={() => onAction(a.id)}>
          <a.icon className="h-3 w-3" />
          {a.label}
        </Button>
      ))}
    </div>
  );
}

// ── 31.3 Persistent Sidebar Co-Pilot ──
function CopilotSidebar({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<{ role: string; content: string; timestamp: string }[]>([]);
  const [isThinking, setIsThinking] = useState(false);
  const [activeSkill, setActiveSkill] = useState<string | null>(null);

  const handleSend = () => {
    if (!input.trim()) return;
    const userMsg = { role: "user", content: input.trim(), timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsThinking(true);

    // Simulate AI response after brief delay
    setTimeout(() => {
      const assistantMsg = {
        role: "assistant",
        content: `I'll analyze that for you. Based on your query "${userMsg.content.slice(0, 60)}...", here are my findings:\n\n- Reviewing available data sources\n- Cross-referencing with threat intelligence\n- Checking compliance posture\n\nPlease run a full investigation via the AI Engine for detailed results.`,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
      setIsThinking(false);
    }, 1500);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed right-0 top-0 h-full w-[380px] bg-background border-l border-border shadow-xl z-50 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b">
        <div className="flex items-center gap-2">
          <Brain className="h-4 w-4 text-cyan-400" />
          <span className="text-sm font-medium">SOC Co-Pilot</span>
          {activeSkill && (
            <Badge variant="outline" className="text-[9px]">
              {activeSkill}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setMessages([])}>
            <History className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={onClose}>
            <XCircle className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Skill selector */}
      <div className="px-3 py-2 border-b">
        <div className="flex flex-wrap gap-1">
          {["threat_intel", "compliance", "remediation", "forensics", "hunting"].map((skill) => (
            <Button
              key={skill}
              variant={activeSkill === skill ? "default" : "outline"}
              size="sm"
              className="h-6 text-[9px] px-2"
              onClick={() => setActiveSkill(activeSkill === skill ? null : skill)}
            >
              {skill.replace(/_/g, " ")}
            </Button>
          ))}
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.length === 0 && (
          <div className="text-center py-8">
            <Brain className="h-10 w-10 mx-auto mb-3 text-muted-foreground/30" />
            <p className="text-sm font-medium">Ask me anything</p>
            <p className="text-xs text-muted-foreground mt-1">
              I can help with triage, threat hunting, compliance, and more
            </p>
            <div className="mt-4">
              <ContextAwareSuggestions
                currentPage="default"
                onSelect={(s) => {
                  setInput(s);
                }}
              />
            </div>
          </div>
        )}
        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-xs ${
                msg.role === "user"
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/50 border border-muted-foreground/10"
              }`}
            >
              {msg.content}
              <div className="text-[9px] opacity-60 mt-1">{new Date(msg.timestamp).toLocaleTimeString()}</div>
            </div>
          </div>
        ))}
        {isThinking && (
          <div className="flex justify-start">
            <div className="bg-muted/50 border border-muted-foreground/10 rounded-lg px-3 py-2 flex items-center gap-2">
              <Loader2 className="h-3 w-3 animate-spin text-primary" />
              <span className="text-xs text-muted-foreground">Thinking...</span>
            </div>
          </div>
        )}
      </div>

      {/* Quick actions */}
      <div className="px-3 py-2 border-t">
        <QuickActionButtons onAction={(a) => setInput(`${a}: `)} />
      </div>

      {/* Input */}
      <div className="p-3 border-t">
        <div className="flex gap-2">
          <Textarea
            value={input}
            onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setInput(e.target.value)}
            placeholder="Ask the co-pilot..."
            className="min-h-[40px] max-h-[100px] text-xs resize-none"
            onKeyDown={(e: React.KeyboardEvent) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
          />
          <Button
            size="sm"
            className="h-10 w-10 p-0 shrink-0"
            onClick={handleSend}
            disabled={!input.trim() || isThinking}
          >
            <Send className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

function FeedbackSection({
  feedback,
  calibrations,
}: {
  feedback: FeedbackRecord[];
  calibrations: PolicyCalibration[];
}) {
  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <MessageSquare className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          Analyst Feedback Log ({feedback.length})
        </h3>
        {feedback.length === 0 ? (
          <Card className="glass-card border-white/5">
            <CardContent className="p-6 text-center">
              <MessageSquare className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
              <p className="text-xs text-muted-foreground">No feedback recorded yet</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {feedback.map((fb) => {
              const outcomeConf = FEEDBACK_OUTCOME_CONFIG[fb.outcome] || FEEDBACK_OUTCOME_CONFIG.accepted;
              return (
                <Card key={fb.id} className="glass-card border-white/5">
                  <CardContent className="p-3">
                    <div className="flex items-center gap-2 flex-wrap mb-2">
                      <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${outcomeConf.color}`}>
                        {outcomeConf.label}
                      </Badge>
                      <Badge
                        variant="outline"
                        className="text-[9px] px-1.5 py-0 h-4 bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                      >
                        {fb.actionType}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground">{fb.analystId}</span>
                      <span className="text-[10px] text-muted-foreground ml-auto">
                        {new Date(fb.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                    <p className="text-xs">
                      <span className="text-muted-foreground">Original:</span> {fb.originalSuggestion}
                    </p>
                    {fb.analystOverride && (
                      <p className="text-xs mt-1">
                        <span className="text-orange-400">Override:</span> {fb.analystOverride}
                      </p>
                    )}
                    <p className="text-xs mt-1">
                      <span className="text-muted-foreground">Reason:</span> {fb.reason}
                    </p>
                    {fb.impactOnPolicy && (
                      <p className="text-xs mt-1">
                        <span className="text-purple-400">Policy Impact:</span> {fb.impactOnPolicy}
                      </p>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-purple-400" aria-hidden="true" />
          Policy Calibrations ({calibrations.length})
        </h3>
        {calibrations.length === 0 ? (
          <Card className="glass-card border-white/5">
            <CardContent className="p-6 text-center">
              <TrendingUp className="h-8 w-8 text-muted-foreground mx-auto mb-2" aria-hidden="true" />
              <p className="text-xs text-muted-foreground">No calibrations recorded yet</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {calibrations.map((cal) => (
              <Card key={cal.id} className="glass-card border-white/5">
                <CardContent className="p-3">
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    <h4 className="text-xs font-semibold">{cal.policyName}</h4>
                    <Badge
                      variant="outline"
                      className="text-[9px] px-1.5 py-0 h-4 bg-purple-500/10 text-purple-400 border-purple-500/20"
                    >
                      {cal.domain}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{cal.triggerReason}</p>
                  <div className="flex items-center gap-4 mt-2">
                    <div className="flex items-center gap-1">
                      <span className="text-[10px] text-muted-foreground">Threshold:</span>
                      <span className="text-[10px] text-red-400 line-through">
                        {(cal.previousThreshold * 100).toFixed(0)}%
                      </span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                      <span className="text-[10px] text-emerald-400">{(cal.newThreshold * 100).toFixed(0)}%</span>
                    </div>
                    <span className="text-[10px] text-muted-foreground">
                      Accept: {(cal.acceptanceRate * 100).toFixed(0)}% &middot; Override:{" "}
                      {(cal.overrideRate * 100).toFixed(0)}%
                    </span>
                    <span className="text-[10px] text-muted-foreground">{cal.feedbackCount} feedbacks</span>
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

export default function SocCopilotPage() {
  const [activeTab, setActiveTab] = useState<TabId>("triage");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedTriages, setExpandedTriages] = useState<Set<string>>(new Set());
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const analystId = user?.id || user?.email || "unknown";

  // 31.3 Persistent Sidebar state
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const { data: stats, isLoading: statsLoading } = useQuery<CopilotStats>({
    queryKey: ["/api/soc-copilot/stats"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/stats");
      return res.json();
    },
  });

  const { data: triages, isLoading: triagesLoading } = useQuery<TriageSummary[]>({
    queryKey: ["/api/soc-copilot/triages"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/triages");
      return res.json();
    },
  });

  const { data: timelines, isLoading: timelinesLoading } = useQuery<CorrelatedTimeline[]>({
    queryKey: ["/api/soc-copilot/timelines"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/timelines");
      return res.json();
    },
  });

  const { data: hypotheses, isLoading: hypothesesLoading } = useQuery<IncidentHypothesis[]>({
    queryKey: ["/api/soc-copilot/hypotheses"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/hypotheses");
      return res.json();
    },
  });

  const { data: actions, isLoading: actionsLoading } = useQuery<AutonomousAction[]>({
    queryKey: ["/api/soc-copilot/actions"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/actions");
      return res.json();
    },
  });

  const { data: feedback, isLoading: feedbackLoading } = useQuery<FeedbackRecord[]>({
    queryKey: ["/api/soc-copilot/feedback"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/feedback");
      return res.json();
    },
  });

  const { data: calibrations, isLoading: calibrationsLoading } = useQuery<PolicyCalibration[]>({
    queryKey: ["/api/soc-copilot/calibrations"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/soc-copilot/calibrations");
      return res.json();
    },
  });

  const updateHypothesisMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const res = await apiRequest("PATCH", `/api/soc-copilot/hypotheses/${id}`, { status });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/hypotheses"] });
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/stats"] });
      toast({ title: "Hypothesis updated" });
    },
  });

  const approveActionMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/soc-copilot/actions/${id}/approve`, {
        analystId,
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/actions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/stats"] });
      toast({ title: "Action approved and executed" });
    },
  });

  const rejectActionMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/soc-copilot/actions/${id}/reject`, {
        analystId,
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/actions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/stats"] });
      toast({ title: "Action rejected" });
    },
  });

  const rollbackActionMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/soc-copilot/actions/${id}/rollback`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/actions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/soc-copilot/stats"] });
      toast({ title: "Action rolled back" });
    },
  });

  const toggleTriageExpand = (id: string) => {
    setExpandedTriages((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredTriages = (triages || []).filter(
    (t) =>
      !searchQuery ||
      t.alertTitle.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.alertId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.verdict.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredHypotheses = (hypotheses || []).filter(
    (h) =>
      !searchQuery ||
      h.hypothesis.toLowerCase().includes(searchQuery.toLowerCase()) ||
      h.incidentId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      h.incidentTitle.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const filteredActions = (actions || []).filter(
    (a) =>
      !searchQuery ||
      a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.targetEntity.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.actionClass.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const tabs: { id: TabId; label: string; icon: typeof Shield; count?: number }[] = [
    { id: "triage", label: "Triage", icon: Shield, count: triages?.length },
    { id: "timeline", label: "Timeline", icon: GitBranch, count: timelines?.length },
    { id: "hypotheses", label: "Hypotheses", icon: Lightbulb, count: hypotheses?.length },
    { id: "actions", label: "Actions", icon: Zap, count: actions?.length },
    { id: "feedback", label: "Feedback & Policy", icon: MessageSquare, count: feedback?.length },
  ];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Brain className="h-5 w-5 text-cyan-400" aria-hidden="true" />
            SOC Co-Pilot
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Analyst acceleration with autonomous enrichment, triage summarization, and policy calibration
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          data-testid="button-toggle-sidebar"
        >
          <PanelRight className="h-3.5 w-3.5 mr-1.5" />
          {sidebarOpen ? "Close" : "Open"} Co-Pilot
        </Button>
      </div>

      {/* 31.3 Persistent Sidebar */}
      <CopilotSidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard label="Triages" value={stats.totalTriages} icon={Shield} accent="bg-blue-500/10" />
          <StatCard label="Auto-Executed" value={stats.autoExecutedActions} icon={Zap} accent="bg-emerald-500/10" />
          <StatCard label="Pending Approvals" value={stats.pendingApprovals} icon={Clock} accent="bg-yellow-500/10" />
          <StatCard
            label="Acceptance Rate"
            value={`${stats.acceptanceRate}%`}
            icon={ThumbsUp}
            accent="bg-emerald-500/10"
          />
          <StatCard label="Override Rate" value={`${stats.overrideRate}%`} icon={RotateCcw} accent="bg-orange-500/10" />
          <StatCard
            label="Avg Confidence"
            value={`${(stats.avgConfidence * 100).toFixed(0)}%`}
            icon={TrendingUp}
            accent="bg-purple-500/10"
          />
        </div>
      ) : null}

      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="glass-card border-white/5">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
                Feedback by Domain
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-4 space-y-2">
              {Object.entries(stats.byDomain).length === 0 ? (
                <p className="text-xs text-muted-foreground">No domain feedback data yet</p>
              ) : (
                Object.entries(stats.byDomain).map(([domain, data]) => {
                  const acceptRate = data.total > 0 ? Math.round((data.accepted / data.total) * 100) : 0;
                  return (
                    <div key={domain} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="capitalize">{domain}</span>
                        <span className="text-muted-foreground">
                          {data.accepted}/{data.total} accepted ({acceptRate}%)
                        </span>
                      </div>
                      <div
                        className="h-1.5 bg-white/5 rounded-full overflow-hidden"
                        role="progressbar"
                        aria-valuenow={acceptRate}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-label={`${domain} acceptance rate`}
                      >
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all duration-500"
                          style={{ width: `${acceptRate}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>

          <Card className="glass-card border-white/5">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="h-4 w-4 text-cyan-400" aria-hidden="true" />
                Actions by Class
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-4 space-y-2">
              {Object.entries(stats.byActionClass).length === 0 ? (
                <p className="text-xs text-muted-foreground">No action class data yet</p>
              ) : (
                Object.entries(stats.byActionClass).map(([cls, data]) => {
                  const classConf = ACTION_CLASS_CONFIG[cls] || { label: cls, color: "" };
                  return (
                    <div
                      key={cls}
                      className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0"
                    >
                      <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 ${classConf.color}`}>
                        {classConf.label}
                      </Badge>
                      <div className="flex items-center gap-3">
                        <span className="text-emerald-400">{data.executed} exec</span>
                        <span className="text-red-400">{data.rejected} rej</span>
                        <span className="text-muted-foreground">{data.total} total</span>
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </div>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <div
          className="flex items-center gap-1 bg-white/5 rounded-lg p-0.5"
          role="tablist"
          aria-label="SOC Co-Pilot sections"
        >
          {tabs.map((tab) => {
            const TabIcon = tab.icon;
            return (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`panel-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-cyan-500/10 text-cyan-400"
                    : "text-muted-foreground hover:text-foreground hover:bg-white/5"
                }`}
              >
                <TabIcon className="h-3.5 w-3.5" aria-hidden="true" />
                {tab.label}
                {tab.count !== undefined && <span className="text-[9px] bg-white/10 px-1 rounded">{tab.count}</span>}
              </button>
            );
          })}
        </div>
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search
            className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 pl-8 text-xs bg-white/5 border-white/10"
            aria-label="Search SOC Co-Pilot data"
          />
        </div>
      </div>

      <div id={`panel-${activeTab}`} role="tabpanel" aria-label={`${activeTab} panel`}>
        {activeTab === "triage" && (
          <div className="space-y-3">
            {triagesLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24" />)
            ) : filteredTriages.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="p-8 text-center">
                  <Shield className="h-10 w-10 text-muted-foreground mx-auto mb-3" aria-hidden="true" />
                  <p className="text-sm font-medium">No triages found</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {searchQuery
                      ? "Try adjusting your search query"
                      : "Generate a triage by selecting an alert for analysis"}
                  </p>
                </CardContent>
              </Card>
            ) : (
              filteredTriages.map((t) => (
                <TriageCard
                  key={t.id}
                  triage={t}
                  isExpanded={expandedTriages.has(t.id)}
                  onToggle={() => toggleTriageExpand(t.id)}
                />
              ))
            )}
          </div>
        )}

        {activeTab === "timeline" && (
          <div className="space-y-3">
            {timelinesLoading ? (
              Array.from({ length: 2 }).map((_, i) => <Skeleton key={i} className="h-24" />)
            ) : !timelines || timelines.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="p-8 text-center">
                  <GitBranch className="h-10 w-10 text-muted-foreground mx-auto mb-3" aria-hidden="true" />
                  <p className="text-sm font-medium">No correlated timelines</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Timelines are generated when incidents are correlated across multiple data sources
                  </p>
                </CardContent>
              </Card>
            ) : (
              timelines.map((tl) => <TimelineCard key={tl.id} timeline={tl} />)
            )}
          </div>
        )}

        {activeTab === "hypotheses" && (
          <div className="space-y-3">
            {hypothesesLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-32" />)
            ) : filteredHypotheses.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="p-8 text-center">
                  <Lightbulb className="h-10 w-10 text-muted-foreground mx-auto mb-3" aria-hidden="true" />
                  <p className="text-sm font-medium">No hypotheses generated</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {searchQuery
                      ? "Try adjusting your search query"
                      : "Hypotheses are suggested when incidents have sufficient data for analysis"}
                  </p>
                </CardContent>
              </Card>
            ) : (
              filteredHypotheses.map((h) => (
                <HypothesisCard
                  key={h.id}
                  hypothesis={h}
                  onUpdateStatus={(status) => updateHypothesisMutation.mutate({ id: h.id, status })}
                  isUpdating={updateHypothesisMutation.isPending}
                />
              ))
            )}
          </div>
        )}

        {activeTab === "actions" && (
          <div className="space-y-3">
            {actionsLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-32" />)
            ) : filteredActions.length === 0 ? (
              <Card className="glass-card border-white/5">
                <CardContent className="p-8 text-center">
                  <Zap className="h-10 w-10 text-muted-foreground mx-auto mb-3" aria-hidden="true" />
                  <p className="text-sm font-medium">No autonomous actions</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {searchQuery
                      ? "Try adjusting your search query"
                      : "Actions are created when the co-pilot identifies enrichment opportunities or containment steps"}
                  </p>
                </CardContent>
              </Card>
            ) : (
              filteredActions.map((a) => (
                <ActionCard
                  key={a.id}
                  action={a}
                  onApprove={() => approveActionMutation.mutate(a.id)}
                  onReject={() => rejectActionMutation.mutate(a.id)}
                  onRollback={() => rollbackActionMutation.mutate(a.id)}
                  isMutating={
                    approveActionMutation.isPending ||
                    rejectActionMutation.isPending ||
                    rollbackActionMutation.isPending
                  }
                />
              ))
            )}
          </div>
        )}

        {activeTab === "feedback" && (
          <>
            {feedbackLoading || calibrationsLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-20" />
                ))}
              </div>
            ) : (
              <FeedbackSection feedback={feedback || []} calibrations={calibrations || []} />
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
          31.1 Context-Aware Suggestions
          ══════════════════════════════════════════════════════════════════════ */}
        <Card data-testid="card-context-suggestions">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-medium">Context-Aware Suggestions</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <ContextAwareSuggestions currentPage="alerts" onSelect={() => setSidebarOpen(true)} />
          </CardContent>
        </Card>

        {/* ══════════════════════════════════════════════════════════════════════
          31.4 Conversation Memory
          ══════════════════════════════════════════════════════════════════════ */}
        <Card data-testid="card-conversation-memory">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-medium">Conversation Memory</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground text-center py-4">
              <MessageSquare className="h-8 w-8 mx-auto mb-2 text-muted-foreground/30" />
              <p>Conversations are persisted across sessions</p>
              <p className="mt-1">Open the Co-Pilot sidebar to start a conversation</p>
            </div>
          </CardContent>
        </Card>

        {/* ══════════════════════════════════════════════════════════════════════
          31.5 Skill-Based Routing
          ══════════════════════════════════════════════════════════════════════ */}
        <Card data-testid="card-skill-routing">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-medium">Skill-Based Prompt Routing</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {[
                { name: "Threat Intel", icon: Shield, desc: "IOCs, actors, campaigns" },
                { name: "Compliance", icon: CheckCircle2, desc: "Audit, SOC2, GDPR" },
                { name: "Remediation", icon: Wrench, desc: "Fix, patch, mitigate" },
                { name: "Forensics", icon: Microscope, desc: "Artifacts, evidence" },
                { name: "Hunting", icon: Crosshair, desc: "Proactive detection" },
                { name: "Incident Response", icon: AlertTriangle, desc: "Contain, eradicate" },
                { name: "Vuln Mgmt", icon: Bug, desc: "CVE, EPSS, CVSS" },
                { name: "Cloud Security", icon: Cloud, desc: "AWS, Azure, GCP" },
              ].map((skill) => (
                <div
                  key={skill.name}
                  className="rounded-md border border-muted-foreground/10 p-2.5 space-y-1 hover:bg-muted/30 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-1.5">
                    <skill.icon className="h-3.5 w-3.5 text-primary" />
                    <span className="text-xs font-medium">{skill.name}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">{skill.desc}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
