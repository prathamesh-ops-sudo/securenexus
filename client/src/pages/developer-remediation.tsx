import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  GitPullRequest,
  Code2,
  Settings,
  FileKey,
  UserCheck,
  ChevronDown,
  ChevronRight,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Users,
  BarChart3,
  ExternalLink,
  Copy,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

type RemediationType = "pull_request" | "ide_fix" | "config_change" | "policy_update" | "access_review";
type RemediationPriority = "critical" | "high" | "medium" | "low";
type RemediationStatus = "suggested" | "in_progress" | "applied" | "dismissed" | "failed";

interface CodeOwner {
  id: string;
  name: string;
  email: string;
  team: string;
  filesOwned: string[];
  reviewCount: number;
  lastActive: string;
}

interface FindingContext {
  source: string;
  rule: string;
  severity: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  message: string;
}

interface CodeChange {
  filePath: string;
  language: string;
  diff: string;
  beforeSnippet: string;
  afterSnippet: string;
  explanation: string;
}

interface RemediationFix {
  id: string;
  type: RemediationType;
  title: string;
  description: string;
  priority: RemediationPriority;
  status: RemediationStatus;
  finding: FindingContext;
  codeChange: CodeChange | null;
  owner: CodeOwner | null;
  estimatedEffort: string;
  mitreTactics: string[];
  cweIds: string[];
  createdAt: string;
  updatedAt: string;
}

interface RemediationStats {
  totalFindings: number;
  suggestedFixes: number;
  appliedFixes: number;
  dismissedFixes: number;
  inProgressFixes: number;
  byPriority: Record<RemediationPriority, number>;
  byType: Record<RemediationType, number>;
  topOwners: { owner: CodeOwner; fixCount: number }[];
  meanTimeToRemediate: string;
  coveragePercent: number;
}

const TYPE_ICONS: Record<RemediationType, typeof GitPullRequest> = {
  pull_request: GitPullRequest,
  ide_fix: Code2,
  config_change: Settings,
  policy_update: FileKey,
  access_review: UserCheck,
};

const TYPE_LABELS: Record<RemediationType, string> = {
  pull_request: "Pull Request",
  ide_fix: "IDE Fix",
  config_change: "Config Change",
  policy_update: "Policy Update",
  access_review: "Access Review",
};

const PRIORITY_COLORS: Record<RemediationPriority, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
};

const STATUS_CONFIG: Record<RemediationStatus, { icon: typeof CheckCircle2; color: string; label: string }> = {
  suggested: { icon: AlertTriangle, color: "text-blue-400", label: "Suggested" },
  in_progress: { icon: Loader2, color: "text-yellow-400", label: "In Progress" },
  applied: { icon: CheckCircle2, color: "text-green-400", label: "Applied" },
  dismissed: { icon: XCircle, color: "text-muted-foreground", label: "Dismissed" },
  failed: { icon: XCircle, color: "text-red-400", label: "Failed" },
};

async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url, { credentials: "include" });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

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

function CodeDiffView({ codeChange }: { codeChange: CodeChange }) {
  const { toast } = useToast();
  const lines = codeChange.diff.split("\n");

  function handleCopy() {
    navigator.clipboard
      .writeText(codeChange.afterSnippet)
      .then(() => {
        toast({ title: "Copied", description: "Fix copied to clipboard" });
      })
      .catch(() => {
        toast({ title: "Copy failed", description: "Unable to access clipboard", variant: "destructive" });
      });
  }

  return (
    <div className="mt-3 rounded-lg border border-border/30 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-muted/30 border-b border-border/30">
        <div className="flex items-center gap-2">
          <Code2 className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
          <span className="text-xs font-mono text-muted-foreground">{codeChange.filePath}</span>
          <Badge variant="outline" className="text-[9px] px-1.5 py-0">
            {codeChange.language}
          </Badge>
        </div>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={handleCopy}>
          <Copy className="h-3 w-3 mr-1" aria-hidden="true" />
          Copy fix
        </Button>
      </div>
      <div className="p-3 bg-background/50 font-mono text-xs overflow-x-auto">
        {lines.map((line, i) => {
          let lineClass = "text-muted-foreground";
          if (line.startsWith("+") && !line.startsWith("+++")) lineClass = "text-green-400 bg-green-500/10";
          else if (line.startsWith("-") && !line.startsWith("---")) lineClass = "text-red-400 bg-red-500/10";
          else if (line.startsWith("@@")) lineClass = "text-cyan-400";
          return (
            <div key={`${codeChange.filePath}-line-${i}`} className={`px-2 py-0.5 ${lineClass}`}>
              {line || "\u00A0"}
            </div>
          );
        })}
      </div>
      <div className="px-3 py-2 bg-muted/20 border-t border-border/30">
        <p className="text-xs text-muted-foreground">{codeChange.explanation}</p>
      </div>
    </div>
  );
}

function FixCard({ fix, expanded, onToggle }: { fix: RemediationFix; expanded: boolean; onToggle: () => void }) {
  const TypeIcon = TYPE_ICONS[fix.type];
  const StatusCfg = STATUS_CONFIG[fix.status];
  const StatusIcon = StatusCfg.icon;

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
      >
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-muted/30 shrink-0 mt-0.5">
            <TypeIcon className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold truncate">{fix.title}</h3>
              <Badge className={`text-[10px] px-1.5 py-0 ${PRIORITY_COLORS[fix.priority]}`}>{fix.priority}</Badge>
              <div className="flex items-center gap-1">
                <StatusIcon
                  className={`h-3 w-3 ${StatusCfg.color} ${fix.status === "in_progress" ? "animate-spin" : ""}`}
                  aria-hidden="true"
                />
                <span className={`text-[10px] ${StatusCfg.color}`}>{StatusCfg.label}</span>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{fix.description}</p>
            <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" aria-hidden="true" />
                {fix.estimatedEffort}
              </span>
              <span>
                {fix.finding.source} / {fix.finding.rule}
              </span>
              {fix.owner && (
                <span className="flex items-center gap-1">
                  <Users className="h-3 w-3" aria-hidden="true" />
                  {fix.owner.name}
                </span>
              )}
              {fix.cweIds.map((cwe) => (
                <Badge key={cwe} variant="outline" className="text-[9px] px-1 py-0">
                  {cwe}
                </Badge>
              ))}
            </div>
          </div>
          <div className="shrink-0">
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-border/20 pt-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Finding</h4>
              <div className="rounded-lg bg-muted/20 p-3 space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-[9px]">
                    {fix.finding.source}
                  </Badge>
                  <Badge variant="outline" className="text-[9px]">
                    {fix.finding.severity}
                  </Badge>
                </div>
                <p className="text-xs font-mono text-muted-foreground">
                  {fix.finding.filePath}:{fix.finding.lineStart}-{fix.finding.lineEnd}
                </p>
                <p className="text-xs text-muted-foreground">{fix.finding.message}</p>
                <pre className="text-[10px] font-mono bg-background/50 rounded p-2 overflow-x-auto mt-2">
                  {fix.finding.snippet}
                </pre>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Owner</h4>
              {fix.owner ? (
                <div className="rounded-lg bg-muted/20 p-3 space-y-1">
                  <p className="text-sm font-medium">{fix.owner.name}</p>
                  <p className="text-xs text-muted-foreground">{fix.owner.email}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge variant="outline" className="text-[9px]">
                      {fix.owner.team}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground">{fix.owner.reviewCount} reviews</span>
                  </div>
                  <div className="mt-2">
                    <p className="text-[10px] text-muted-foreground font-semibold">Files owned:</p>
                    {fix.owner.filesOwned.map((f) => (
                      <p key={f} className="text-[10px] font-mono text-muted-foreground">
                        {f}
                      </p>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="rounded-lg bg-muted/20 p-3 text-xs text-muted-foreground">No owner assigned</div>
              )}
            </div>
          </div>

          {fix.mitreTactics.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                MITRE Tactics
              </h4>
              <div className="flex gap-1 flex-wrap">
                {fix.mitreTactics.map((t) => (
                  <Badge key={t} variant="outline" className="text-[9px] capitalize">
                    {t.replace(/-/g, " ")}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {fix.codeChange && <CodeDiffView codeChange={fix.codeChange} />}

          <div className="flex gap-2 pt-2">
            {fix.status === "suggested" && (
              <>
                <Button size="sm" className="h-7 text-xs gap-1">
                  <GitPullRequest className="h-3 w-3" aria-hidden="true" />
                  Create PR
                </Button>
                <Button size="sm" variant="outline" className="h-7 text-xs gap-1">
                  <ExternalLink className="h-3 w-3" aria-hidden="true" />
                  Open in IDE
                </Button>
              </>
            )}
            {fix.status === "in_progress" && (
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1">
                <ExternalLink className="h-3 w-3" aria-hidden="true" />
                View PR
              </Button>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

function OwnerCard({ owner, fixCount }: { owner: CodeOwner; fixCount: number }) {
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/20">
      <div className="flex items-center justify-center w-8 h-8 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold">
        {owner.name
          .split(" ")
          .map((n) => n[0])
          .join("")}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{owner.name}</p>
        <p className="text-[10px] text-muted-foreground">{owner.team}</p>
      </div>
      <div className="text-right">
        <p className="text-sm font-bold">{fixCount}</p>
        <p className="text-[10px] text-muted-foreground">fixes</p>
      </div>
    </div>
  );
}

export default function DeveloperRemediationPage() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filterPriority, setFilterPriority] = useState<RemediationPriority | "all">("all");
  const [filterType, setFilterType] = useState<RemediationType | "all">("all");
  const [filterStatus, setFilterStatus] = useState<RemediationStatus | "all">("all");

  const { data: fixes, isLoading: fixesLoading } = useQuery<RemediationFix[]>({
    queryKey: ["/api/remediation/fixes"],
    queryFn: () => apiFetch("/api/remediation/fixes"),
  });

  const { data: stats, isLoading: statsLoading } = useQuery<RemediationStats>({
    queryKey: ["/api/remediation/stats"],
    queryFn: () => apiFetch("/api/remediation/stats"),
  });

  const filteredFixes = (fixes ?? []).filter((f) => {
    if (filterPriority !== "all" && f.priority !== filterPriority) return false;
    if (filterType !== "all" && f.type !== filterType) return false;
    if (filterStatus !== "all" && f.status !== filterStatus) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Developer-Native Remediation</h1>
        <p className="text-sm text-muted-foreground mt-1">
          PR/IDE fix guidance with code ownership mapping and MITRE context
        </p>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={`stat-skeleton-${i}`} className="h-24" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Total Findings"
            value={stats.totalFindings}
            icon={Shield}
            color="bg-cyan-500/20 text-cyan-400"
          />
          <StatCard
            label="Applied Fixes"
            value={stats.appliedFixes}
            icon={CheckCircle2}
            color="bg-green-500/20 text-green-400"
          />
          <StatCard
            label="Coverage"
            value={`${stats.coveragePercent}%`}
            icon={BarChart3}
            color="bg-blue-500/20 text-blue-400"
          />
          <StatCard
            label="Mean Time to Remediate"
            value={stats.meanTimeToRemediate}
            icon={Clock}
            color="bg-purple-500/20 text-purple-400"
          />
        </div>
      ) : (
        <div className="text-center py-8 text-sm text-muted-foreground">No stats available</div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 space-y-4">
          <Card className="glass-card border-border/30">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <CardTitle className="text-base">Remediation Queue</CardTitle>
                <div className="flex items-center gap-2">
                  <select
                    className="text-xs bg-background border border-border/50 rounded px-2 py-1"
                    value={filterPriority}
                    onChange={(e) => setFilterPriority(e.target.value as RemediationPriority | "all")}
                    aria-label="Filter by priority"
                  >
                    <option value="all">All priorities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select
                    className="text-xs bg-background border border-border/50 rounded px-2 py-1"
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value as RemediationType | "all")}
                    aria-label="Filter by type"
                  >
                    <option value="all">All types</option>
                    {Object.entries(TYPE_LABELS).map(([k, v]) => (
                      <option key={k} value={k}>
                        {v}
                      </option>
                    ))}
                  </select>
                  <select
                    className="text-xs bg-background border border-border/50 rounded px-2 py-1"
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value as RemediationStatus | "all")}
                    aria-label="Filter by status"
                  >
                    <option value="all">All statuses</option>
                    <option value="suggested">Suggested</option>
                    <option value="in_progress">In Progress</option>
                    <option value="applied">Applied</option>
                    <option value="dismissed">Dismissed</option>
                    <option value="failed">Failed</option>
                  </select>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {fixesLoading ? (
                Array.from({ length: 3 }).map((_, i) => <Skeleton key={`fix-skeleton-${i}`} className="h-24" />)
              ) : filteredFixes.length === 0 ? (
                <div className="text-center py-12">
                  <Shield className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" aria-hidden="true" />
                  <p className="text-sm text-muted-foreground">No remediation items match the current filters</p>
                </div>
              ) : (
                filteredFixes.map((fix) => (
                  <FixCard
                    key={fix.id}
                    fix={fix}
                    expanded={expandedId === fix.id}
                    onToggle={() => setExpandedId(expandedId === fix.id ? null : fix.id)}
                  />
                ))
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card className="glass-card border-border/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Priority Breakdown</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {stats ? (
                Object.entries(stats.byPriority).map(([priority, count]) => (
                  <div key={priority} className="flex items-center justify-between">
                    <Badge className={`text-[10px] capitalize ${PRIORITY_COLORS[priority as RemediationPriority]}`}>
                      {priority}
                    </Badge>
                    <span className="text-sm font-bold">{count}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted-foreground">No data available</p>
              )}
            </CardContent>
          </Card>

          <Card className="glass-card border-border/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Fix Types</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {stats ? (
                Object.entries(stats.byType).map(([type, count]) => {
                  const Icon = TYPE_ICONS[type as RemediationType];
                  return (
                    <div key={type} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Icon className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                        <span className="text-xs">{TYPE_LABELS[type as RemediationType]}</span>
                      </div>
                      <span className="text-sm font-bold">{count}</span>
                    </div>
                  );
                })
              ) : (
                <p className="text-xs text-muted-foreground">No data available</p>
              )}
            </CardContent>
          </Card>

          <Card className="glass-card border-border/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Top Code Owners</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {stats && stats.topOwners.length > 0 ? (
                stats.topOwners.map((entry) => (
                  <OwnerCard key={entry.owner.id} owner={entry.owner} fixCount={entry.fixCount} />
                ))
              ) : (
                <p className="text-xs text-muted-foreground">No owner data available</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
