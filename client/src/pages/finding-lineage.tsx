import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  ChevronDown,
  ChevronRight,
  GitPullRequest,
  Code2,
  Copy,
  ExternalLink,
  Users,
  Server,
  FileCode,
  Package,
  Search,
  Filter,
  BarChart3,
  Target,
  Fingerprint,
  MapPin,
  Building2,
  Phone,
  Hash,
  FileText,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
type FindingSource =
  | "sast"
  | "dast"
  | "sca"
  | "container_scan"
  | "iac_scan"
  | "secret_scan"
  | "cloud_config"
  | "runtime"
  | "pentest"
  | "manual";
type FindingStatus = "open" | "in_progress" | "remediated" | "suppressed" | "false_positive";
type ConfidenceLevel = "confirmed" | "high" | "medium" | "low" | "unknown";

interface SourceLocation {
  repo: string;
  branch: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  rule: string;
  language: string;
  commitSha: string;
}

interface BuildContext {
  pipelineName: string;
  pipelineId: string;
  jobName: string;
  jobId: string;
  buildNumber: number;
  artifactHash: string;
  registry: string;
  imageTag: string;
  triggeredAt: string;
}

interface DeployedAsset {
  assetId: string;
  assetName: string;
  assetType: string;
  environment: string;
  region: string;
  namespace: string;
  lastDeployedAt: string;
  infraProvider: string;
}

interface OwnerInfo {
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  team: string;
  escalationPath: string[];
  slackChannel: string;
  oncallSchedule: string;
}

interface EvidenceBundle {
  id: string;
  findingId: string;
  evidenceType: string;
  title: string;
  content: string;
  collectedAt: string;
  sourceUrl: string;
}

interface RemediationSuggestion {
  id: string;
  findingId: string;
  title: string;
  description: string;
  patchDiff: string;
  filePath: string;
  language: string;
  confidenceScore: number;
  effort: string;
  prReady: boolean;
  cweIds: string[];
  references: string[];
  createdAt: string;
}

interface FindingLineage {
  id: string;
  orgId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  source: FindingSource;
  status: FindingStatus;
  confidence: ConfidenceLevel;
  riskScore: number;
  sourceLocation: SourceLocation;
  buildContext: BuildContext | null;
  deployedAsset: DeployedAsset;
  owner: OwnerInfo;
  evidenceBundles: EvidenceBundle[];
  remediationSuggestions: RemediationSuggestion[];
  correlationHash: string;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  slaDeadline: string;
  cveIds: string[];
  cweIds: string[];
  mitreTactics: string[];
}

interface LineageStats {
  totalFindings: number;
  openFindings: number;
  remediatedFindings: number;
  suppressedFindings: number;
  bySeverity: Record<FindingSeverity, number>;
  bySource: Record<string, number>;
  byEnvironment: Record<string, number>;
  meanTimeToRemediate: string;
  slaBreaches: number;
  patchReadySuggestions: number;
  avgConfidenceScore: number;
  topOwners: { owner: OwnerInfo; findingCount: number }[];
}

const SEVERITY_COLORS: Record<FindingSeverity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
  info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const STATUS_CONFIG: Record<FindingStatus, { icon: typeof CheckCircle2; color: string; label: string }> = {
  open: { icon: AlertTriangle, color: "text-red-400", label: "Open" },
  in_progress: {
    icon: Loader2,
    color: "text-yellow-400",
    label: "In Progress",
  },
  remediated: {
    icon: CheckCircle2,
    color: "text-green-400",
    label: "Remediated",
  },
  suppressed: {
    icon: XCircle,
    color: "text-muted-foreground",
    label: "Suppressed",
  },
  false_positive: {
    icon: XCircle,
    color: "text-muted-foreground",
    label: "False Positive",
  },
};

const SOURCE_LABELS: Record<FindingSource, string> = {
  sast: "SAST",
  dast: "DAST",
  sca: "SCA",
  container_scan: "Container",
  iac_scan: "IaC",
  secret_scan: "Secrets",
  cloud_config: "Cloud Config",
  runtime: "Runtime",
  pentest: "Pentest",
  manual: "Manual",
};

const CONFIDENCE_COLORS: Record<ConfidenceLevel, string> = {
  confirmed: "bg-green-500/20 text-green-400",
  high: "bg-cyan-500/20 text-cyan-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-orange-500/20 text-orange-400",
  unknown: "bg-muted text-muted-foreground",
};

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: typeof Shield;
  color: string;
}) {
  return (
    <Card className="glass-card border-border/30">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
          </div>
          <div className={`p-2 rounded-lg ${color}`}>
            <Icon className="h-5 w-5" aria-hidden="true" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function RiskScoreBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  let barColor = "bg-green-500";
  if (pct >= 90) barColor = "bg-red-500";
  else if (pct >= 70) barColor = "bg-orange-500";
  else if (pct >= 50) barColor = "bg-yellow-500";

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-muted/30 rounded-full overflow-hidden">
        <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono font-bold w-10 text-right">{pct}%</span>
    </div>
  );
}

function ConfidenceBadge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  let color = "bg-muted text-muted-foreground";
  if (pct >= 90) color = "bg-green-500/20 text-green-400";
  else if (pct >= 75) color = "bg-cyan-500/20 text-cyan-400";
  else if (pct >= 50) color = "bg-yellow-500/20 text-yellow-400";
  else color = "bg-orange-500/20 text-orange-400";

  return <Badge className={`text-[10px] px-1.5 py-0 ${color}`}>{pct}% confidence</Badge>;
}

function PatchDiffView({ suggestion }: { suggestion: RemediationSuggestion }) {
  const { toast } = useToast();
  const lines = suggestion.patchDiff.split("\n");

  function handleCopy() {
    navigator.clipboard
      .writeText(suggestion.patchDiff)
      .then(() => {
        toast({ title: "Copied", description: "Patch diff copied to clipboard" });
      })
      .catch(() => {
        toast({
          title: "Copy failed",
          description: "Unable to access clipboard",
          variant: "destructive",
        });
      });
  }

  return (
    <div className="rounded-lg border border-border/30 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-muted/30 border-b border-border/30">
        <div className="flex items-center gap-2">
          <Code2 className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
          <span className="text-xs font-mono text-muted-foreground">{suggestion.filePath}</span>
          <Badge variant="outline" className="text-[9px] px-1.5 py-0">
            {suggestion.language}
          </Badge>
          <ConfidenceBadge score={suggestion.confidenceScore} />
        </div>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={handleCopy}>
          <Copy className="h-3 w-3 mr-1" aria-hidden="true" />
          Copy
        </Button>
      </div>
      <div className="p-3 bg-background/50 font-mono text-xs overflow-x-auto">
        {lines.map((line, i) => {
          let lineClass = "text-muted-foreground";
          if (line.startsWith("+") && !line.startsWith("+++")) lineClass = "text-green-400 bg-green-500/10";
          else if (line.startsWith("-") && !line.startsWith("---")) lineClass = "text-red-400 bg-red-500/10";
          else if (line.startsWith("@@")) lineClass = "text-cyan-400";
          return (
            <div key={`${suggestion.id}-line-${i}`} className={`px-2 py-0.5 ${lineClass}`}>
              {line || "\u00A0"}
            </div>
          );
        })}
      </div>
      <div className="px-3 py-2 bg-muted/20 border-t border-border/30">
        <p className="text-xs text-muted-foreground">{suggestion.description}</p>
      </div>
    </div>
  );
}

function EvidenceCard({ evidence }: { evidence: EvidenceBundle }) {
  const typeIcons: Record<string, typeof FileText> = {
    code_snippet: Code2,
    log_trace: Activity,
    network_capture: Server,
    config_snapshot: FileCode,
    scan_report: FileText,
  };
  const Icon = typeIcons[evidence.evidenceType] || FileText;

  return (
    <div className="rounded-lg border border-border/30 overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-muted/30 border-b border-border/30">
        <Icon className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
        <span className="text-xs font-medium">{evidence.title}</span>
        <Badge variant="outline" className="text-[9px] px-1.5 py-0 ml-auto">
          {evidence.evidenceType.replace(/_/g, " ")}
        </Badge>
      </div>
      <pre className="p-3 text-[11px] font-mono text-muted-foreground bg-background/50 overflow-x-auto whitespace-pre-wrap">
        {evidence.content}
      </pre>
      <div className="px-3 py-1.5 bg-muted/20 border-t border-border/30 flex items-center justify-between">
        <span className="text-[10px] text-muted-foreground">
          Collected {new Date(evidence.collectedAt).toLocaleDateString()}
        </span>
        {evidence.sourceUrl && (
          <a
            href={evidence.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
          >
            <ExternalLink className="h-3 w-3" aria-hidden="true" />
            Source
          </a>
        )}
      </div>
    </div>
  );
}

function LineageChain({ finding }: { finding: FindingLineage }) {
  const steps = [
    {
      label: "Source Code",
      icon: FileCode,
      detail: `${finding.sourceLocation.repo} — ${finding.sourceLocation.filePath}:${finding.sourceLocation.lineStart}`,
      sub: `Branch: ${finding.sourceLocation.branch} | Rule: ${finding.sourceLocation.rule} | Commit: ${finding.sourceLocation.commitSha.slice(0, 7)}`,
    },
    finding.buildContext
      ? {
          label: "Build Pipeline",
          icon: Package,
          detail: `${finding.buildContext.pipelineName} — Job: ${finding.buildContext.jobName}`,
          sub: `Build #${finding.buildContext.buildNumber} | Image: ${finding.buildContext.imageTag} | Hash: ${finding.buildContext.artifactHash.slice(0, 20)}...`,
        }
      : null,
    {
      label: "Deployed Asset",
      icon: Server,
      detail: `${finding.deployedAsset.assetName} (${finding.deployedAsset.assetType})`,
      sub: `Env: ${finding.deployedAsset.environment} | Region: ${finding.deployedAsset.region} | Provider: ${finding.deployedAsset.infraProvider}`,
    },
    {
      label: "Business Owner",
      icon: Users,
      detail: `${finding.owner.ownerName} — ${finding.owner.team}`,
      sub: `Escalation: ${finding.owner.escalationPath.join(" → ")}`,
    },
  ].filter(Boolean) as {
    label: string;
    icon: typeof FileCode;
    detail: string;
    sub: string;
  }[];

  return (
    <div className="space-y-0">
      {steps.map((step, idx) => (
        <div key={step.label} className="flex gap-3">
          <div className="flex flex-col items-center">
            <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <step.icon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            </div>
            {idx < steps.length - 1 && <div className="w-px h-8 bg-border/50 my-1" />}
          </div>
          <div className="pb-4 min-w-0 flex-1">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">{step.label}</p>
            <p className="text-xs font-medium mt-0.5 truncate">{step.detail}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{step.sub}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingCard({
  finding,
  expanded,
  onToggle,
}: {
  finding: FindingLineage;
  expanded: boolean;
  onToggle: () => void;
}) {
  const [activeTab, setActiveTab] = useState<"lineage" | "evidence" | "remediation" | "owner">("lineage");
  const StatusCfg = STATUS_CONFIG[finding.status];
  const StatusIcon = StatusCfg.icon;
  const slaDate = new Date(finding.slaDeadline);
  const isSlaBreach = finding.status !== "remediated" && finding.status !== "false_positive" && slaDate < new Date();

  return (
    <Card className="glass-card border-border/30 hover:border-border/50 transition-colors">
      <div
        className="p-4 cursor-pointer"
        onClick={onToggle}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") onToggle();
        }}
        aria-expanded={expanded}
        aria-label={`Finding: ${finding.title}`}
      >
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-muted/30 shrink-0 mt-0.5">
            <Shield className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold truncate">{finding.title}</h3>
              <Badge className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[finding.severity]}`}>
                {finding.severity}
              </Badge>
              <div className="flex items-center gap-1">
                <StatusIcon
                  className={`h-3 w-3 ${StatusCfg.color} ${finding.status === "in_progress" ? "animate-spin" : ""}`}
                  aria-hidden="true"
                />
                <span className={`text-[10px] ${StatusCfg.color}`}>{StatusCfg.label}</span>
              </div>
              <Badge className={`text-[10px] px-1.5 py-0 ${CONFIDENCE_COLORS[finding.confidence]}`}>
                {finding.confidence}
              </Badge>
              {isSlaBreach && (
                <Badge className="text-[10px] px-1.5 py-0 bg-red-500/20 text-red-400 border-red-500/30">
                  SLA Breached
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{finding.description}</p>
            <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground flex-wrap">
              <span className="flex items-center gap-1">
                <Target className="h-3 w-3" aria-hidden="true" />
                Risk: {Math.round(finding.riskScore * 100)}%
              </span>
              <span>
                {SOURCE_LABELS[finding.source]} / {finding.sourceLocation.rule}
              </span>
              <span className="flex items-center gap-1">
                <Users className="h-3 w-3" aria-hidden="true" />
                {finding.owner.ownerName}
              </span>
              <span className="flex items-center gap-1">
                <Server className="h-3 w-3" aria-hidden="true" />
                {finding.deployedAsset.environment}
              </span>
              {finding.cweIds.map((cwe) => (
                <Badge key={cwe} variant="outline" className="text-[9px] px-1 py-0">
                  {cwe}
                </Badge>
              ))}
              {finding.cveIds.map((cve) => (
                <Badge key={cve} variant="outline" className="text-[9px] px-1 py-0 border-red-500/30 text-red-400">
                  {cve}
                </Badge>
              ))}
            </div>
          </div>
          <div className="shrink-0 flex flex-col items-end gap-1">
            <div className="w-16">
              <RiskScoreBar score={finding.riskScore} />
            </div>
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border/20">
          <div className="flex border-b border-border/20">
            {(
              [
                { key: "lineage", label: "Lineage Chain", icon: MapPin },
                {
                  key: "evidence",
                  label: `Evidence (${finding.evidenceBundles.length})`,
                  icon: Fingerprint,
                },
                {
                  key: "remediation",
                  label: `Fixes (${finding.remediationSuggestions.length})`,
                  icon: GitPullRequest,
                },
                { key: "owner", label: "Owner & Escalation", icon: Building2 },
              ] as const
            ).map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  activeTab === tab.key
                    ? "border-cyan-400 text-cyan-400"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                <tab.icon className="h-3.5 w-3.5" aria-hidden="true" />
                {tab.label}
              </button>
            ))}
          </div>

          <div className="p-4 space-y-4">
            {activeTab === "lineage" && <LineageChain finding={finding} />}

            {activeTab === "evidence" && (
              <div className="space-y-3">
                {finding.evidenceBundles.length === 0 ? (
                  <div className="text-center py-8">
                    <Fingerprint className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No evidence collected yet</p>
                  </div>
                ) : (
                  finding.evidenceBundles.map((ev) => <EvidenceCard key={ev.id} evidence={ev} />)
                )}
              </div>
            )}

            {activeTab === "remediation" && (
              <div className="space-y-4">
                {finding.remediationSuggestions.length === 0 ? (
                  <div className="text-center py-8">
                    <GitPullRequest className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No remediation suggestions yet</p>
                  </div>
                ) : (
                  finding.remediationSuggestions.map((s) => (
                    <div key={s.id} className="space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h4 className="text-sm font-medium">{s.title}</h4>
                        <ConfidenceBadge score={s.confidenceScore} />
                        <Badge variant="outline" className="text-[9px] px-1.5 py-0">
                          Effort: {s.effort}
                        </Badge>
                        {s.prReady && (
                          <Badge className="text-[9px] px-1.5 py-0 bg-green-500/20 text-green-400 border-green-500/30">
                            PR Ready
                          </Badge>
                        )}
                      </div>
                      <PatchDiffView suggestion={s} />
                      {s.cweIds.length > 0 && (
                        <div className="flex gap-1 flex-wrap">
                          {s.cweIds.map((c) => (
                            <Badge key={c} variant="outline" className="text-[9px] px-1 py-0">
                              {c}
                            </Badge>
                          ))}
                        </div>
                      )}
                      {s.references.length > 0 && (
                        <div className="flex gap-2 flex-wrap">
                          {s.references.map((ref) => (
                            <a
                              key={ref}
                              href={ref}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                            >
                              <ExternalLink className="h-3 w-3" aria-hidden="true" />
                              {(() => {
                                try {
                                  return new URL(ref).hostname;
                                } catch {
                                  return ref;
                                }
                              })()}
                            </a>
                          ))}
                        </div>
                      )}
                      <div className="flex gap-2 pt-1">
                        {s.prReady && (
                          <Button size="sm" className="h-7 text-xs gap-1">
                            <GitPullRequest className="h-3 w-3" aria-hidden="true" />
                            Create PR
                          </Button>
                        )}
                        <Button size="sm" variant="outline" className="h-7 text-xs gap-1">
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                          Open in IDE
                        </Button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {activeTab === "owner" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                    Business Owner
                  </h4>
                  <div className="rounded-lg bg-muted/20 p-4 space-y-2">
                    <div className="flex items-center gap-3">
                      <div className="flex items-center justify-center w-10 h-10 rounded-full bg-cyan-500/20 text-cyan-400 text-sm font-bold">
                        {finding.owner.ownerName
                          .split(" ")
                          .map((n) => n[0])
                          .join("")}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{finding.owner.ownerName}</p>
                        <p className="text-xs text-muted-foreground">{finding.owner.ownerEmail}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <Badge variant="outline" className="text-[9px]">
                        {finding.owner.team}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-1.5 mt-2">
                      <Hash className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                      <span className="text-xs text-muted-foreground">{finding.owner.slackChannel}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Phone className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                      <span className="text-xs text-muted-foreground">{finding.owner.oncallSchedule}</span>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                    Escalation Path
                  </h4>
                  <div className="rounded-lg bg-muted/20 p-4">
                    {finding.owner.escalationPath.map((person, idx) => (
                      <div key={person} className="flex items-center gap-2">
                        <div className="flex flex-col items-center">
                          <div
                            className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                              idx === 0 ? "bg-cyan-500/20 text-cyan-400" : "bg-muted/50 text-muted-foreground"
                            }`}
                          >
                            {idx + 1}
                          </div>
                          {idx < finding.owner.escalationPath.length - 1 && (
                            <div className="w-px h-4 bg-border/50 my-0.5" />
                          )}
                        </div>
                        <span className="text-xs">{person}</span>
                      </div>
                    ))}
                  </div>

                  {finding.mitreTactics.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                        MITRE ATT&CK Tactics
                      </h4>
                      <div className="flex gap-1 flex-wrap">
                        {finding.mitreTactics.map((t) => (
                          <Badge key={t} variant="outline" className="text-[9px] capitalize">
                            {t.replace(/-/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      SLA Deadline
                    </h4>
                    <div
                      className={`flex items-center gap-2 ${isSlaBreach ? "text-red-400" : "text-muted-foreground"}`}
                    >
                      <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                      <span className="text-xs">
                        {slaDate.toLocaleDateString()} {slaDate.toLocaleTimeString()}
                      </span>
                      {isSlaBreach && (
                        <Badge className="text-[9px] px-1.5 py-0 bg-red-500/20 text-red-400">BREACHED</Badge>
                      )}
                    </div>
                  </div>

                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      Correlation Hash
                    </h4>
                    <p className="text-[10px] font-mono text-muted-foreground">{finding.correlationHash}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

function TopOwnersPanel({ topOwners }: { topOwners: { owner: OwnerInfo; findingCount: number }[] }) {
  return (
    <Card className="glass-card border-border/30">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Users className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          Top Finding Owners
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {topOwners.map((entry) => (
          <div key={entry.owner.ownerId} className="flex items-center gap-3 p-2 rounded-lg bg-muted/20">
            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold">
              {entry.owner.ownerName
                .split(" ")
                .map((n) => n[0])
                .join("")}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium truncate">{entry.owner.ownerName}</p>
              <p className="text-[10px] text-muted-foreground">{entry.owner.team}</p>
            </div>
            <div className="text-right">
              <p className="text-sm font-bold">{entry.findingCount}</p>
              <p className="text-[10px] text-muted-foreground">findings</p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export default function FindingLineagePage() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<FindingSeverity | "all">("all");
  const [filterSource, setFilterSource] = useState<FindingSource | "all">("all");
  const [filterStatus, setFilterStatus] = useState<FindingStatus | "all">("all");
  const [filterEnv, setFilterEnv] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");

  const { data: findings, isLoading: findingsLoading } = useQuery<FindingLineage[]>({
    queryKey: ["/api/finding-lineage"],
  });

  const { data: stats, isLoading: statsLoading } = useQuery<LineageStats>({
    queryKey: ["/api/finding-lineage/stats"],
  });

  const filteredFindings = (findings ?? []).filter((f) => {
    if (filterSeverity !== "all" && f.severity !== filterSeverity) return false;
    if (filterSource !== "all" && f.source !== filterSource) return false;
    if (filterStatus !== "all" && f.status !== filterStatus) return false;
    if (filterEnv !== "all" && f.deployedAsset.environment !== filterEnv) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        f.title.toLowerCase().includes(term) ||
        f.description.toLowerCase().includes(term) ||
        f.sourceLocation.filePath.toLowerCase().includes(term) ||
        f.sourceLocation.rule.toLowerCase().includes(term) ||
        f.owner.ownerName.toLowerCase().includes(term) ||
        f.cweIds.some((c) => c.toLowerCase().includes(term)) ||
        f.cveIds.some((c) => c.toLowerCase().includes(term))
      );
    }
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Code-to-Production Finding Lineage</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Trace high-risk findings from source code through build pipelines to deployed assets with exact owner and fix
          point mapping
        </p>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={`stat-skeleton-${i}`} className="h-24" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard
            label="Total Findings"
            value={stats.totalFindings}
            icon={Shield}
            color="bg-cyan-500/20 text-cyan-400"
          />
          <StatCard label="Open" value={stats.openFindings} icon={AlertTriangle} color="bg-red-500/20 text-red-400" />
          <StatCard
            label="Remediated"
            value={stats.remediatedFindings}
            icon={CheckCircle2}
            color="bg-green-500/20 text-green-400"
          />
          <StatCard
            label="SLA Breaches"
            value={stats.slaBreaches}
            icon={Clock}
            color="bg-orange-500/20 text-orange-400"
          />
          <StatCard
            label="PR-Ready Patches"
            value={stats.patchReadySuggestions}
            icon={GitPullRequest}
            color="bg-blue-500/20 text-blue-400"
          />
          <StatCard
            label="Mean Remediation"
            value={stats.meanTimeToRemediate}
            icon={BarChart3}
            color="bg-purple-500/20 text-purple-400"
          />
        </div>
      ) : (
        <div className="text-center py-8 text-sm text-muted-foreground">Unable to load stats</div>
      )}

      <div className="flex flex-col md:flex-row gap-3 items-start md:items-center flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search findings, CWEs, CVEs, owners..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 h-9 text-sm glass-subtle"
            aria-label="Search findings"
          />
        </div>
        <div className="flex gap-2 flex-wrap items-center">
          <Filter className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value as FindingSeverity | "all")}
            className="h-9 px-3 rounded-md border border-border/50 bg-background text-xs"
            aria-label="Filter by severity"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            value={filterSource}
            onChange={(e) => setFilterSource(e.target.value as FindingSource | "all")}
            className="h-9 px-3 rounded-md border border-border/50 bg-background text-xs"
            aria-label="Filter by source"
          >
            <option value="all">All Sources</option>
            {Object.entries(SOURCE_LABELS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as FindingStatus | "all")}
            className="h-9 px-3 rounded-md border border-border/50 bg-background text-xs"
            aria-label="Filter by status"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="remediated">Remediated</option>
            <option value="suppressed">Suppressed</option>
            <option value="false_positive">False Positive</option>
          </select>
          <select
            value={filterEnv}
            onChange={(e) => setFilterEnv(e.target.value)}
            className="h-9 px-3 rounded-md border border-border/50 bg-background text-xs"
            aria-label="Filter by environment"
          >
            <option value="all">All Environments</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 space-y-3">
          {findingsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={`finding-skeleton-${i}`} className="h-28" />)
          ) : filteredFindings.length === 0 ? (
            <div className="text-center py-16">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
              <h3 className="text-lg font-medium">No findings found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {searchTerm ||
                filterSeverity !== "all" ||
                filterSource !== "all" ||
                filterStatus !== "all" ||
                filterEnv !== "all"
                  ? "Try adjusting your search or filter criteria"
                  : "No security findings have been ingested yet"}
              </p>
            </div>
          ) : (
            filteredFindings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                expanded={expandedId === f.id}
                onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
              />
            ))
          )}
        </div>

        <div className="space-y-4">
          {stats && stats.topOwners.length > 0 && <TopOwnersPanel topOwners={stats.topOwners} />}

          {stats && (
            <Card className="glass-card border-border/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
                  By Severity
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                  const count = stats.bySeverity[sev] || 0;
                  const total = stats.totalFindings || 1;
                  return (
                    <div key={sev} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs capitalize">{sev}</span>
                        <span className="text-xs font-mono">{count}</span>
                      </div>
                      <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            sev === "critical"
                              ? "bg-red-500"
                              : sev === "high"
                                ? "bg-orange-500"
                                : sev === "medium"
                                  ? "bg-yellow-500"
                                  : sev === "low"
                                    ? "bg-green-500"
                                    : "bg-blue-500"
                          }`}
                          style={{
                            width: `${(count / total) * 100}%`,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {stats && (
            <Card className="glass-card border-border/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Target className="h-4 w-4 text-cyan-400" aria-hidden="true" />
                  Avg Confidence
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-3">
                  <div className="text-3xl font-bold">{Math.round(stats.avgConfidenceScore * 100)}%</div>
                  <div className="flex-1">
                    <RiskScoreBar score={stats.avgConfidenceScore} />
                  </div>
                </div>
                <p className="text-[10px] text-muted-foreground mt-2">
                  Average confidence score across all remediation suggestions
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
