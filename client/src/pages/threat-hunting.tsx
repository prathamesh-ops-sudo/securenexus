import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Search,
  Plus,
  Play,
  Trash2,
  Clock,
  Target,
  BookOpen,
  Brain,
  Shield,
  Code,
  Calendar,
  BarChart3,
  Crosshair,
  Loader2,
  Share2,
  Download,
  Lightbulb,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ArrowRight,
  FileWarning,
  Link2,
  Plug,
  Notebook,
  Users,
  Zap,
  Database,
  TrendingUp,
  TrendingDown,
  Minus,
  Eye,
  Send,
  ThumbsUp,
  Globe,
  FileText,
  Layers,
  Timer,
  Hash,
  MessageSquare,
  StopCircle,
  ChevronDown,
  ChevronRight,
  Copy,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { EmptyState } from "@/components/empty-state";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { DashboardSkeleton } from "@/components/page-skeleton";
import { ReadOnlyActionNotice } from "@/components/read-only-action-notice";
import { useOrgContext } from "@/hooks/use-org-context";

// ─── Types ──────────────────────────────────────────────────────────────────

interface ThreatHunt {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  queryType: string;
  queryText: string;
  compiledQuery: string | null;
  status: string;
  hypothesis: string | null;
  mitreTechniques: string[];
  tags: string[];
  lastRunAt: string | null;
  lastRunDurationMs: number | null;
  lastRunEventCount: number | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

interface HuntResult {
  id: string;
  huntId: string;
  eventCount: number;
  eventsJson: Record<string, unknown>[];
  summary: string | null;
  falsePositiveCount: number | null;
  truePositiveCount: number | null;
  executionDurationMs: number | null;
  executedAt: string;
  executedBy: string | null;
  linkedIncidentId: string | null;
}

interface HuntScheduleRow {
  schedule: {
    id: string;
    huntId: string;
    cadence: string;
    dayOfWeek: number | null;
    hourUtc: number;
    enabled: boolean;
    nextRunAt: string | null;
    lastRunAt: string | null;
    createdAt: string;
  };
  huntName: string | null;
  huntQueryType: string | null;
}

interface LibraryEntry {
  library: {
    id: string;
    huntId: string;
    isPublic: boolean;
    sharedBy: string | null;
    category: string | null;
    difficulty: string | null;
    rating: number | null;
    downloadCount: number | null;
    sharedAt: string;
  };
  huntName: string | null;
  huntDescription: string | null;
  huntQueryType: string | null;
  huntQueryText: string | null;
}

interface HuntPlaybook {
  id: string;
  name: string;
  description: string | null;
  threatActor: string | null;
  mitreTechniques: string[];
  steps: {
    order: number;
    title: string;
    description: string;
    queryType: string;
    queryText: string;
    expectedOutcome: string;
  }[];
  difficulty: string | null;
  estimatedTimeMin: number | null;
  datasourcesRequired: string[];
  createdAt: string;
}

interface Hypothesis {
  hypothesis: string;
  queryType: string;
  suggestedQuery: string;
  mitreTechnique: string;
  confidence: string;
}

interface MitreCoverage {
  [techniqueId: string]: {
    huntCount: number;
    huntNames: string[];
    lastRun: string | null;
  };
}

// ─── 16.x New Types ─────────────────────────────────────────────────────────

interface NotebookStep {
  id: string;
  title: string;
  queryType: string;
  queryText: string;
  notes: string;
  resultSummary: string | null;
  eventCount: number | null;
  lastExecutedAt: string | null;
  outputVariables: Record<string, unknown>;
}

interface HuntNotebook {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  steps: NotebookStep[];
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

interface CollaborationSession {
  id: string;
  orgId: string;
  huntId: string | null;
  sessionName: string;
  participants: { userId: string; name: string; color: string; joinedAt: string }[];
  sharedResults: Record<string, unknown>[];
  chatMessages: { userId: string; name: string; message: string; timestamp: string }[];
  status: string;
  startedAt: string;
  endedAt: string | null;
}

interface ExecutionPlan {
  queryType: string;
  dataSources: string[];
  estimatedRows: number;
  estimatedTimeMs: number;
  optimizations: string[];
  warnings: string[];
  steps: { phase: string; description: string; estimatedMs: number }[];
}

interface CacheEntry {
  id: string;
  queryHash: string;
  queryType: string;
  queryText: string;
  resultJson: Record<string, unknown>;
  eventCount: number;
  executionDurationMs: number | null;
  ttlSeconds: number;
  hitCount: number;
  cachedAt: string;
  expiresAt: string;
  isExpired: boolean;
}

interface DriftEntry {
  drift: {
    id: string;
    scheduleId: string;
    huntId: string;
    previousEventCount: number;
    currentEventCount: number;
    driftPercentage: number;
    driftDirection: string;
    isSignificant: boolean;
    detectedAt: string;
    acknowledged: boolean;
  };
  huntName: string | null;
}

interface CommunityShare {
  id: string;
  orgId: string;
  huntId: string;
  title: string;
  description: string | null;
  queryType: string;
  queryText: string;
  category: string | null;
  mitreTechniques: string[];
  tags: string[];
  anonymizedStats: { detectionRate: number; avgExecutionMs: number; totalRuns: number };
  upvotes: number;
  downloads: number;
  sharedBy: string | null;
  sharedAt: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function statusColor(status: string): string {
  switch (status) {
    case "completed":
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    case "running":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    case "failed":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "rejected":
      return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "ready":
      return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    case "draft":
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function queryTypeIcon(qt: string): string {
  switch (qt) {
    case "sigma":
      return "S";
    case "yara":
      return "Y";
    case "kql":
      return "K";
    case "sql":
      return "Q";
    default:
      return "C";
  }
}

function queryTypeLabel(qt: string): string {
  switch (qt) {
    case "sigma":
      return "Sigma";
    case "yara":
      return "YARA";
    case "kql":
      return "KQL";
    case "sql":
      return "SQL";
    case "custom":
      return "Custom";
    default:
      return qt;
  }
}

function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatDate(d: string | null): string {
  if (!d) return "-";
  return new Date(d).toLocaleString();
}

const MITRE_TACTICS = [
  { id: "TA0001", name: "Initial Access", techniques: ["T1189", "T1190", "T1133", "T1566", "T1078", "T1195"] },
  { id: "TA0002", name: "Execution", techniques: ["T1059", "T1203", "T1047", "T1053", "T1569"] },
  { id: "TA0003", name: "Persistence", techniques: ["T1098", "T1197", "T1547", "T1136", "T1053", "T1505"] },
  { id: "TA0004", name: "Privilege Escalation", techniques: ["T1548", "T1134", "T1068", "T1055", "T1078"] },
  { id: "TA0005", name: "Defense Evasion", techniques: ["T1140", "T1070", "T1036", "T1027", "T1218", "T1562"] },
  { id: "TA0006", name: "Credential Access", techniques: ["T1110", "T1003", "T1056", "T1552", "T1539"] },
  { id: "TA0007", name: "Discovery", techniques: ["T1087", "T1082", "T1083", "T1046", "T1135", "T1018"] },
  { id: "TA0008", name: "Lateral Movement", techniques: ["T1021", "T1080", "T1534", "T1570", "T1563"] },
  { id: "TA0009", name: "Collection", techniques: ["T1560", "T1005", "T1039", "T1114", "T1074"] },
  { id: "TA0010", name: "Exfiltration", techniques: ["T1041", "T1048", "T1567", "T1052", "T1020"] },
  { id: "TA0011", name: "Command & Control", techniques: ["T1071", "T1132", "T1001", "T1573", "T1008"] },
  { id: "TA0040", name: "Impact", techniques: ["T1485", "T1486", "T1565", "T1499", "T1529"] },
];

// ─── Components ─────────────────────────────────────────────────────────────

function StatsCards({
  stats,
}: {
  stats: { totalHunts: number; totalExecutions: number; activeSchedules: number; totalPlaybooks: number };
}) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Card>
        <CardContent className="pt-4 pb-3">
          <div className="flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-cyan-400" />
            <span className="text-xs text-muted-foreground">Total Hunts</span>
          </div>
          <p className="text-2xl font-bold mt-1">{stats.totalHunts}</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3">
          <div className="flex items-center gap-2">
            <Play className="h-4 w-4 text-emerald-400" />
            <span className="text-xs text-muted-foreground">Executions</span>
          </div>
          <p className="text-2xl font-bold mt-1">{stats.totalExecutions}</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3">
          <div className="flex items-center gap-2">
            <Calendar className="h-4 w-4 text-amber-400" />
            <span className="text-xs text-muted-foreground">Active Schedules</span>
          </div>
          <p className="text-2xl font-bold mt-1">{stats.activeSchedules}</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3">
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-violet-400" />
            <span className="text-xs text-muted-foreground">Playbooks</span>
          </div>
          <p className="text-2xl font-bold mt-1">{stats.totalPlaybooks}</p>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Query Builder Tab ──────────────────────────────────────────────────────

function QueryBuilderTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [queryType, setQueryType] = useState("sigma");
  const [queryText, setQueryText] = useState("");
  const [hypothesis, setHypothesis] = useState("");
  const [mitreTechniques, setMitreTechniques] = useState("");
  const [selectedHunt, setSelectedHunt] = useState<ThreatHunt | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const { data: huntsData, isLoading } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/hunts", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/hunts"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Hunt created" });
      setOpen(false);
      resetForm();
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const executeMutation = useMutation({
    mutationFn: (huntId: string) =>
      apiRequest("POST", `/api/threat-hunting/hunts/${huntId}/execute`, { limit: 100 }).then((r) => r.json()),
    onSuccess: (data: { execution: { eventCount: number; executionDurationMs: number } }) => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/hunts"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({
        title: "Hunt executed",
        description: `Found ${data.execution.eventCount} events in ${formatDuration(data.execution.executionDurationMs)}`,
      });
    },
    onError: (e: Error) => toast({ title: "Execution failed", description: e.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (huntId: string) => apiRequest("DELETE", `/api/threat-hunting/hunts/${huntId}`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/hunts"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Hunt deleted" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function resetForm() {
    setName("");
    setDescription("");
    setQueryType("sigma");
    setQueryText("");
    setHypothesis("");
    setMitreTechniques("");
  }

  const hunts = huntsData?.hunts || [];

  const placeholders: Record<string, string> = {
    sigma: `title: Suspicious PowerShell Execution
description: Detect encoded PowerShell commands
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
level: high`,
    yara: `rule SuspiciousDocument {
  strings:
    $s1 = "powershell" nocase
    $s2 = "cmd.exe /c" nocase
    $hex = { 4D 5A 90 00 }
  condition:
    any of them
}`,
    kql: `alerts
| where severity == "critical"
| where status != "resolved"
| where category contains "malware"`,
    sql: `SELECT * FROM alerts
WHERE severity = 'critical'
  AND status != 'resolved'
ORDER BY created_at DESC
LIMIT 100`,
    custom: "Enter your custom query here...",
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Query Builder</h3>
          <p className="text-sm text-muted-foreground">
            Create and execute threat hunts using Sigma, YARA, KQL, or SQL
          </p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> New Hunt
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Threat Hunt</DialogTitle>
              <DialogDescription>Define a hunt query using your preferred query language</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Name</Label>
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Hunt name" />
                </div>
                <div>
                  <Label>Query Type</Label>
                  <Select value={queryType} onValueChange={setQueryType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="sigma">Sigma Rule</SelectItem>
                      <SelectItem value="yara">YARA Rule</SelectItem>
                      <SelectItem value="kql">KQL Query</SelectItem>
                      <SelectItem value="sql">SQL Query</SelectItem>
                      <SelectItem value="custom">Custom</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label>Description</Label>
                <Input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What does this hunt detect?"
                />
              </div>
              <div>
                <Label>Hypothesis</Label>
                <Input
                  value={hypothesis}
                  onChange={(e) => setHypothesis(e.target.value)}
                  placeholder="What are you trying to prove/disprove?"
                />
              </div>
              <div>
                <Label>MITRE ATT&CK Techniques (comma-separated)</Label>
                <Input
                  value={mitreTechniques}
                  onChange={(e) => setMitreTechniques(e.target.value)}
                  placeholder="T1059, T1053, T1003"
                />
              </div>
              <div>
                <Label>Query</Label>
                <SyntaxHighlightedEditor
                  value={queryText}
                  onChange={setQueryText}
                  queryType={queryType}
                  placeholder={placeholders[queryType] || ""}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() =>
                  createMutation.mutate({
                    name,
                    description,
                    queryType,
                    queryText,
                    hypothesis,
                    mitreTechniques: mitreTechniques
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  })
                }
                disabled={!name || !queryText || createMutation.isPending}
              >
                {createMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                ) : (
                  <Plus className="h-4 w-4 mr-1" />
                )}
                Create Hunt
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : hunts.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState
              icon={Crosshair}
              title="No threat hunts created yet"
              description="Threat hunting requires log data from connected sources. Create a hunt using Sigma, YARA, KQL, or SQL queries to proactively search for threats."
              action={{
                label: "Create Your First Hunt",
                icon: Plus,
                onClick: () => setOpen(true),
              }}
            />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {hunts.map((hunt) => (
            <Card key={hunt.id} className="hover:border-primary/30 transition-colors">
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex-shrink-0 w-8 h-8 rounded bg-primary/10 flex items-center justify-center font-mono text-xs font-bold text-primary">
                      {queryTypeIcon(hunt.queryType)}
                    </div>
                    <div className="min-w-0">
                      <button
                        className="text-sm font-medium hover:underline cursor-pointer text-left truncate block max-w-md"
                        onClick={() => {
                          setSelectedHunt(hunt);
                          setDetailOpen(true);
                        }}
                      >
                        {hunt.name}
                      </button>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant="outline" className={`text-[10px] ${statusColor(hunt.status)}`}>
                          {hunt.status}
                        </Badge>
                        <span className="text-[10px] text-muted-foreground">{queryTypeLabel(hunt.queryType)}</span>
                        {hunt.lastRunEventCount !== null && (
                          <span className="text-[10px] text-muted-foreground">{hunt.lastRunEventCount} events</span>
                        )}
                        {hunt.lastRunAt && (
                          <span className="text-[10px] text-muted-foreground">
                            Last run {formatDate(hunt.lastRunAt)}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => executeMutation.mutate(hunt.id)}
                      disabled={executeMutation.isPending}
                      title="Execute hunt"
                    >
                      {executeMutation.isPending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Play className="h-3 w-3" />
                      )}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => deleteMutation.mutate(hunt.id)}
                      disabled={deleteMutation.isPending}
                      title="Delete hunt"
                    >
                      <Trash2 className="h-3 w-3 text-destructive" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Hunt Detail Dialog */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          {selectedHunt && <HuntDetailView hunt={selectedHunt} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function HuntDetailView({ hunt }: { hunt: ThreatHunt }) {
  const { data: detailData } = useQuery<{ hunt: ThreatHunt; results: HuntResult[] }>({
    queryKey: [`/api/threat-hunting/hunts/${hunt.id}`],
  });

  const results = detailData?.results || [];

  return (
    <div className="space-y-4">
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2">
          <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center font-mono text-xs font-bold text-primary">
            {queryTypeIcon(hunt.queryType)}
          </div>
          {hunt.name}
        </DialogTitle>
        <DialogDescription>{hunt.description || "No description"}</DialogDescription>
      </DialogHeader>

      <div className="grid grid-cols-3 gap-3 text-sm">
        <div>
          <span className="text-muted-foreground">Status</span>
          <Badge variant="outline" className={`ml-2 ${statusColor(hunt.status)}`}>
            {hunt.status}
          </Badge>
        </div>
        <div>
          <span className="text-muted-foreground">Type: </span>
          <span>{queryTypeLabel(hunt.queryType)}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Last run: </span>
          <span>{formatDate(hunt.lastRunAt)}</span>
        </div>
      </div>

      {hunt.hypothesis && (
        <div className="p-3 bg-amber-500/5 border border-amber-500/20 rounded-md">
          <div className="flex items-center gap-2 text-amber-400 text-xs font-medium mb-1">
            <Lightbulb className="h-3 w-3" /> Hypothesis
          </div>
          <p className="text-sm">{hunt.hypothesis}</p>
        </div>
      )}

      {(hunt.mitreTechniques as string[]).length > 0 && (
        <div className="flex items-center gap-1 flex-wrap">
          <Shield className="h-3 w-3 text-muted-foreground mr-1" />
          {(hunt.mitreTechniques as string[]).map((t) => (
            <Badge key={t} variant="secondary" className="text-[10px]">
              {t}
            </Badge>
          ))}
        </div>
      )}

      <div>
        <Label className="text-xs text-muted-foreground">Query</Label>
        <pre className="mt-1 p-3 bg-muted/50 rounded text-xs font-mono overflow-auto max-h-48 whitespace-pre-wrap">
          {hunt.queryText}
        </pre>
      </div>

      {/* 16.5 Execution Plan */}
      <ExecutionPlanPanel huntId={hunt.id} />

      {/* 16.8 & 16.9 Action Buttons */}
      <div className="flex items-center gap-2">
        <EscalateHuntButton huntId={hunt.id} huntName={hunt.name} />
        <ConvertToRuleButton huntId={hunt.id} huntName={hunt.name} />
      </div>

      {results.length > 0 && (
        <div>
          <Label className="text-xs text-muted-foreground">Recent Results</Label>
          <div className="mt-1 space-y-2">
            {results.slice(0, 5).map((r) => (
              <div key={r.id} className="flex items-center justify-between p-2 bg-muted/30 rounded text-xs">
                <div className="flex items-center gap-2">
                  {r.eventCount > 0 ? (
                    <AlertTriangle className="h-3 w-3 text-amber-400" />
                  ) : (
                    <CheckCircle2 className="h-3 w-3 text-green-500" />
                  )}
                  <span>{r.eventCount} events found</span>
                </div>
                <div className="flex items-center gap-3 text-muted-foreground">
                  <span>{formatDuration(r.executionDurationMs)}</span>
                  <span>{formatDate(r.executedAt)}</span>
                </div>
              </div>
            ))}
          </div>
          {/* 16.2 Result Visualization */}
          <div className="mt-3">
            <ResultVisualizationPanel results={results} />
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Hunt Library Tab ───────────────────────────────────────────────────────

function HuntLibraryTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [category, setCategory] = useState<string>("");
  const [difficulty, setDifficulty] = useState<string>("");
  const [shareOpen, setShareOpen] = useState(false);
  const [shareHuntId, setShareHuntId] = useState("");
  const [shareCategory, setShareCategory] = useState("other");
  const [shareDifficulty, setShareDifficulty] = useState("intermediate");
  const [sharePublic, setSharePublic] = useState(false);

  const queryParams = new URLSearchParams();
  if (category) queryParams.set("category", category);
  if (difficulty) queryParams.set("difficulty", difficulty);

  const { data: libraryData, isLoading } = useQuery<{ entries: LibraryEntry[] }>({
    queryKey: ["/api/threat-hunting/library", category, difficulty],
    queryFn: () => apiRequest("GET", `/api/threat-hunting/library?${queryParams.toString()}`).then((r) => r.json()),
  });

  const { data: huntsData } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const shareMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/library", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/library"] });
      toast({ title: "Hunt shared to library" });
      setShareOpen(false);
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const entries = libraryData?.entries || [];
  const hunts = huntsData?.hunts || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Hunt Library</h3>
          <p className="text-sm text-muted-foreground">Browse and share community hunt queries</p>
        </div>
        <Dialog open={shareOpen} onOpenChange={setShareOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Share2 className="h-4 w-4 mr-1" /> Share Hunt
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Share Hunt to Library</DialogTitle>
              <DialogDescription>Make your hunt available to the community</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Select Hunt</Label>
                <Select value={shareHuntId} onValueChange={setShareHuntId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a hunt..." />
                  </SelectTrigger>
                  <SelectContent>
                    {hunts.map((h) => (
                      <SelectItem key={h.id} value={h.id}>
                        {h.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Category</Label>
                  <Select value={shareCategory} onValueChange={setShareCategory}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="apt">APT</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                      <SelectItem value="insider_threat">Insider Threat</SelectItem>
                      <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
                      <SelectItem value="credential_access">Credential Access</SelectItem>
                      <SelectItem value="data_exfiltration">Data Exfiltration</SelectItem>
                      <SelectItem value="persistence">Persistence</SelectItem>
                      <SelectItem value="c2">C2</SelectItem>
                      <SelectItem value="other">Other</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Difficulty</Label>
                  <Select value={shareDifficulty} onValueChange={setShareDifficulty}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="beginner">Beginner</SelectItem>
                      <SelectItem value="intermediate">Intermediate</SelectItem>
                      <SelectItem value="advanced">Advanced</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={sharePublic} onCheckedChange={setSharePublic} />
                <Label>Make publicly available</Label>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShareOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() =>
                  shareMutation.mutate({
                    huntId: shareHuntId,
                    isPublic: sharePublic,
                    category: shareCategory,
                    difficulty: shareDifficulty,
                  })
                }
                disabled={!shareHuntId || shareMutation.isPending}
              >
                Share
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex items-center gap-2">
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            <SelectItem value="apt">APT</SelectItem>
            <SelectItem value="ransomware">Ransomware</SelectItem>
            <SelectItem value="insider_threat">Insider Threat</SelectItem>
            <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
            <SelectItem value="credential_access">Credential Access</SelectItem>
            <SelectItem value="persistence">Persistence</SelectItem>
            <SelectItem value="c2">C2</SelectItem>
          </SelectContent>
        </Select>
        <Select value={difficulty} onValueChange={setDifficulty}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Difficulty" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Levels</SelectItem>
            <SelectItem value="beginner">Beginner</SelectItem>
            <SelectItem value="intermediate">Intermediate</SelectItem>
            <SelectItem value="advanced">Advanced</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : entries.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <BookOpen className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-muted-foreground">
              No library entries yet. Share your hunts to build a community library.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {entries.map((entry) => (
            <Card key={entry.library.id}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">{entry.huntName || "Unnamed Hunt"}</CardTitle>
                  <div className="flex items-center gap-1">
                    {entry.library.isPublic && (
                      <Badge variant="outline" className="text-[10px]">
                        Public
                      </Badge>
                    )}
                    <Badge variant="secondary" className="text-[10px]">
                      {entry.huntQueryType || "?"}
                    </Badge>
                  </div>
                </div>
                <CardDescription className="text-xs">{entry.huntDescription || "No description"}</CardDescription>
              </CardHeader>
              <CardContent className="pb-3">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  {entry.library.category && (
                    <Badge variant="outline" className="text-[10px]">
                      {entry.library.category}
                    </Badge>
                  )}
                  {entry.library.difficulty && (
                    <Badge variant="outline" className="text-[10px]">
                      {entry.library.difficulty}
                    </Badge>
                  )}
                  <span className="ml-auto">
                    <Download className="h-3 w-3 inline mr-1" />
                    {entry.library.downloadCount || 0}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Hunt Schedules Tab ─────────────────────────────────────────────────────

function HuntSchedulesTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [huntId, setHuntId] = useState("");
  const [cadence, setCadence] = useState("weekly");
  const [dayOfWeek, setDayOfWeek] = useState("1");
  const [hourUtc, setHourUtc] = useState("8");

  const { data: schedulesData, isLoading } = useQuery<{ schedules: HuntScheduleRow[] }>({
    queryKey: ["/api/threat-hunting/schedules"],
  });

  const { data: huntsData } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/schedules", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/schedules"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Schedule created" });
      setCreateOpen(false);
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: (scheduleId: string) =>
      apiRequest("PATCH", `/api/threat-hunting/schedules/${scheduleId}/toggle`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/schedules"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (scheduleId: string) =>
      apiRequest("DELETE", `/api/threat-hunting/schedules/${scheduleId}`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/schedules"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Schedule deleted" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const schedules = schedulesData?.schedules || [];
  const hunts = huntsData?.hunts || [];

  const DOW_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Hunt Schedules</h3>
          <p className="text-sm text-muted-foreground">Configure recurring hunts to run automatically</p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> New Schedule
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Hunt Schedule</DialogTitle>
              <DialogDescription>Schedule a hunt to run automatically at regular intervals</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Select Hunt</Label>
                <Select value={huntId} onValueChange={setHuntId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a hunt..." />
                  </SelectTrigger>
                  <SelectContent>
                    {hunts.map((h) => (
                      <SelectItem key={h.id} value={h.id}>
                        {h.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label>Cadence</Label>
                  <Select value={cadence} onValueChange={setCadence}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="daily">Daily</SelectItem>
                      <SelectItem value="weekly">Weekly</SelectItem>
                      <SelectItem value="biweekly">Biweekly</SelectItem>
                      <SelectItem value="monthly">Monthly</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Day of Week</Label>
                  <Select value={dayOfWeek} onValueChange={setDayOfWeek}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {DOW_LABELS.map((label, i) => (
                        <SelectItem key={i} value={String(i)}>
                          {label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Hour (UTC)</Label>
                  <Input type="number" min={0} max={23} value={hourUtc} onChange={(e) => setHourUtc(e.target.value)} />
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() =>
                  createMutation.mutate({
                    huntId,
                    cadence,
                    dayOfWeek: Number(dayOfWeek),
                    hourUtc: Number(hourUtc),
                  })
                }
                disabled={!huntId || createMutation.isPending}
              >
                Create Schedule
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : schedules.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Calendar className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-muted-foreground">
              No schedules configured. Set up recurring hunts to automate your threat detection.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Hunt</TableHead>
              <TableHead>Cadence</TableHead>
              <TableHead>Next Run</TableHead>
              <TableHead>Last Run</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead className="w-20">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {schedules.map((row) => (
              <TableRow key={row.schedule.id}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-[10px]">
                      {row.huntQueryType || "?"}
                    </Badge>
                    <span className="text-sm">{row.huntName || "Unknown Hunt"}</span>
                  </div>
                </TableCell>
                <TableCell className="capitalize text-sm">{row.schedule.cadence}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{formatDate(row.schedule.nextRunAt)}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{formatDate(row.schedule.lastRunAt)}</TableCell>
                <TableCell>
                  <Switch
                    checked={row.schedule.enabled}
                    onCheckedChange={() => toggleMutation.mutate(row.schedule.id)}
                  />
                </TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => deleteMutation.mutate(row.schedule.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="h-3 w-3 text-destructive" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// ─── Hunt Results Tab ───────────────────────────────────────────────────────

function HuntResultsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedHuntId, setSelectedHuntId] = useState<string>("");
  const [linkDialogResultId, setLinkDialogResultId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");

  const { data: huntsData } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const { data: resultsData, isLoading } = useQuery<{ results: HuntResult[] }>({
    queryKey: [`/api/threat-hunting/results/${selectedHuntId}`],
    enabled: !!selectedHuntId,
  });

  const { data: incidentsData } = useQuery<{ incidents: Array<{ id: string; title: string; status: string }> }>({
    queryKey: ["/api/incidents"],
    enabled: !!linkDialogResultId,
  });

  const createIncidentMutation = useMutation({
    mutationFn: (resultId: string) =>
      apiRequest("POST", `/api/threat-hunting/results/${resultId}/create-incident`).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Incident created from hunt result" });
      queryClient.invalidateQueries({ queryKey: [`/api/threat-hunting/results/${selectedHuntId}`] });
    },
    onError: (e: Error) =>
      toast({ title: "Failed to create incident", description: e.message, variant: "destructive" }),
  });

  const linkIncidentMutation = useMutation({
    mutationFn: ({ resultId, incidentId }: { resultId: string; incidentId: string }) =>
      apiRequest("PATCH", `/api/threat-hunting/results/${resultId}/link-incident`, { incidentId }).then((r) =>
        r.json(),
      ),
    onSuccess: () => {
      toast({ title: "Hunt result linked to incident" });
      setLinkDialogResultId(null);
      setSelectedIncidentId("");
      queryClient.invalidateQueries({ queryKey: [`/api/threat-hunting/results/${selectedHuntId}`] });
    },
    onError: (e: Error) => toast({ title: "Failed to link incident", description: e.message, variant: "destructive" }),
  });

  const hunts = huntsData?.hunts || [];
  const results = resultsData?.results || [];
  const existingIncidents = incidentsData?.incidents || [];

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">Hunt Results</h3>
        <p className="text-sm text-muted-foreground">View execution results and matched events</p>
      </div>

      <div>
        <Select value={selectedHuntId} onValueChange={setSelectedHuntId}>
          <SelectTrigger className="w-80">
            <SelectValue placeholder="Select a hunt to view results..." />
          </SelectTrigger>
          <SelectContent>
            {hunts.map((h) => (
              <SelectItem key={h.id} value={h.id}>
                {h.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {!selectedHuntId ? (
        <Card>
          <CardContent className="py-12 text-center">
            <BarChart3 className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-muted-foreground">Select a hunt to view its execution results.</p>
          </CardContent>
        </Card>
      ) : isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : results.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">No results yet. Execute the hunt to see results.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {/* 16.2 Result Visualization Panel */}
          <ResultVisualizationPanel results={results} />

          {results.map((r) => (
            <Card key={r.id}>
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    {r.eventCount > 0 ? (
                      <AlertTriangle className="h-5 w-5 text-amber-400" />
                    ) : (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    )}
                    <div>
                      <p className="text-sm font-medium">{r.eventCount} events matched</p>
                      <p className="text-xs text-muted-foreground">
                        Executed {formatDate(r.executedAt)} in {formatDuration(r.executionDurationMs)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {r.linkedIncidentId ? (
                      <Badge variant="outline" className="text-emerald-400 border-emerald-500/30">
                        <Link2 className="h-3 w-3 mr-1" />
                        Linked
                      </Badge>
                    ) : r.eventCount > 0 ? (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs gap-1"
                          onClick={() => createIncidentMutation.mutate(r.id)}
                          disabled={createIncidentMutation.isPending}
                        >
                          <FileWarning className="h-3 w-3" />
                          Create Incident
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 text-xs gap-1"
                          onClick={() => setLinkDialogResultId(r.id)}
                        >
                          <Link2 className="h-3 w-3" />
                          Link to Incident
                        </Button>
                      </>
                    ) : null}
                  </div>
                </div>
                {r.eventCount > 0 && Array.isArray(r.eventsJson) && r.eventsJson.length > 0 && (
                  <ScrollArea className="max-h-48">
                    <pre className="text-[10px] font-mono p-2 bg-muted/30 rounded overflow-auto">
                      {JSON.stringify(r.eventsJson.slice(0, 5), null, 2)}
                    </pre>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Link to Incident Dialog */}
      <Dialog
        open={!!linkDialogResultId}
        onOpenChange={(open) => {
          if (!open) {
            setLinkDialogResultId(null);
            setSelectedIncidentId("");
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Link to Existing Incident</DialogTitle>
            <DialogDescription>Select an incident to attach this hunt result as evidence.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <Select value={selectedIncidentId} onValueChange={setSelectedIncidentId}>
              <SelectTrigger>
                <SelectValue placeholder="Select an incident..." />
              </SelectTrigger>
              <SelectContent>
                {existingIncidents.map((inc) => (
                  <SelectItem key={inc.id} value={inc.id}>
                    {inc.title} ({inc.status})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => {
                setLinkDialogResultId(null);
                setSelectedIncidentId("");
              }}
            >
              Cancel
            </Button>
            <Button
              disabled={!selectedIncidentId || linkIncidentMutation.isPending}
              onClick={() => {
                if (linkDialogResultId && selectedIncidentId) {
                  linkIncidentMutation.mutate({ resultId: linkDialogResultId, incidentId: selectedIncidentId });
                }
              }}
            >
              {linkIncidentMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Link2 className="h-4 w-4 mr-1" />
              )}
              Link
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Pivot Interface Tab ────────────────────────────────────────────────────

function PivotTab() {
  const { isPlatformAdminReadOnly } = useOrgContext();
  const { toast } = useToast();
  const [iocType, setIocType] = useState("ip");
  const [iocValue, setIocValue] = useState("");

  const pivotMutation = useMutation({
    mutationFn: () =>
      apiRequest("POST", `/api/threat-hunting/pivot/${iocType}/${encodeURIComponent(iocValue)}`).then((r) => r.json()),
    onError: (e: Error) => toast({ title: "Pivot failed", description: e.message, variant: "destructive" }),
  });

  const result = pivotMutation.data as
    | { alerts: Record<string, unknown>[]; ingestionLogs: Record<string, unknown>[]; totalHits: number }
    | undefined;

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">Pivot Interface</h3>
        <p className="text-sm text-muted-foreground">
          Click an IOC and instantly see all related activity across your data
        </p>
      </div>

      <div className="flex items-center gap-3">
        <Select value={iocType} onValueChange={setIocType}>
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ip">IP Address</SelectItem>
            <SelectItem value="domain">Domain</SelectItem>
            <SelectItem value="hash">File Hash</SelectItem>
            <SelectItem value="email">Email</SelectItem>
            <SelectItem value="url">URL</SelectItem>
            <SelectItem value="file">Filename</SelectItem>
            <SelectItem value="cve">CVE ID</SelectItem>
          </SelectContent>
        </Select>
        <Input
          value={iocValue}
          onChange={(e) => setIocValue(e.target.value)}
          placeholder="Enter IOC value..."
          className="flex-1"
          onKeyDown={(e) => {
            if (e.key === "Enter" && iocValue && !isPlatformAdminReadOnly) pivotMutation.mutate();
          }}
        />
        <Button
          onClick={() => pivotMutation.mutate()}
          disabled={!iocValue || pivotMutation.isPending || isPlatformAdminReadOnly}
        >
          {pivotMutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Search className="h-4 w-4 mr-1" />
          )}
          Pivot
        </Button>
      </div>
      <ReadOnlyActionNotice />

      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Target className="h-4 w-4 text-cyan-400" />
            <span className="text-sm font-medium">{result.totalHits} total matches found</span>
          </div>

          {result.alerts.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Matching Alerts ({result.alerts.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="max-h-64">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Title</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Created</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {result.alerts.map((a, i) => (
                        <TableRow key={i}>
                          <TableCell className="text-sm">{String(a.title || "")}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-[10px]">
                              {String(a.severity || "")}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-sm">{String(a.status || "")}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDate(String(a.created_at || ""))}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          )}

          {result.ingestionLogs.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Matching Ingestion Logs ({result.ingestionLogs.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="max-h-48">
                  <pre className="text-[10px] font-mono p-2 bg-muted/30 rounded">
                    {JSON.stringify(result.ingestionLogs.slice(0, 10), null, 2)}
                  </pre>
                </ScrollArea>
              </CardContent>
            </Card>
          )}

          {result.totalHits === 0 && (
            <Card>
              <CardContent className="py-8 text-center">
                <CheckCircle2 className="h-8 w-8 text-green-500" />
                <p className="text-muted-foreground">No matches found for this IOC across your data.</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Hypothesis-Driven Hunting Tab ──────────────────────────────────────────

function HypothesisTab() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: hypothesesData, isLoading } = useQuery<{ hypotheses: Hypothesis[] }>({
    queryKey: ["/api/threat-hunting/hypotheses"],
  });

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/hunts", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/hunts"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Hunt created from hypothesis" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const hypotheses = hypothesesData?.hypotheses || [];

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">Hypothesis-Driven Hunting</h3>
        <p className="text-sm text-muted-foreground">AI-generated hunt hypotheses based on your alert patterns</p>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : hypotheses.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Brain className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-muted-foreground">
              No hypotheses available. Ingest more alerts to generate AI-driven hunt suggestions.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {hypotheses.map((h, i) => (
            <Card key={i}>
              <CardContent className="py-4 px-4">
                <div className="flex items-start gap-3">
                  <Lightbulb className="h-5 w-5 text-amber-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium mb-1">{h.hypothesis}</p>
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="secondary" className="text-[10px]">
                        {h.mitreTechnique}
                      </Badge>
                      <Badge variant="outline" className="text-[10px]">
                        {queryTypeLabel(h.queryType)}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={`text-[10px] ${h.confidence === "high" ? "text-red-400 border-red-500/30" : "text-amber-400 border-amber-500/30"}`}
                      >
                        {h.confidence} confidence
                      </Badge>
                    </div>
                    <pre className="text-[10px] font-mono p-2 bg-muted/30 rounded max-h-32 overflow-auto whitespace-pre-wrap">
                      {h.suggestedQuery}
                    </pre>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      createMutation.mutate({
                        name: `Hypothesis: ${h.mitreTechnique}`,
                        description: h.hypothesis,
                        queryType: h.queryType,
                        queryText: h.suggestedQuery,
                        hypothesis: h.hypothesis,
                        mitreTechniques: [h.mitreTechnique],
                      })
                    }
                    disabled={createMutation.isPending}
                  >
                    <ArrowRight className="h-3 w-3 mr-1" /> Create Hunt
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Hunt Playbooks Tab ─────────────────────────────────────────────────────

function PlaybooksTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [threatActor, setThreatActor] = useState("");
  const [difficulty, setDifficulty] = useState("intermediate");
  const [selectedPlaybook, setSelectedPlaybook] = useState<HuntPlaybook | null>(null);

  const { data: playbooksData, isLoading } = useQuery<{ playbooks: HuntPlaybook[] }>({
    queryKey: ["/api/threat-hunting/playbooks"],
  });

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/playbooks", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/playbooks"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Playbook created" });
      setCreateOpen(false);
      setName("");
      setDescription("");
      setThreatActor("");
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/threat-hunting/playbooks/${id}`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/playbooks"] });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/stats"] });
      toast({ title: "Playbook deleted" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const playbooks = playbooksData?.playbooks || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Hunt Playbooks</h3>
          <p className="text-sm text-muted-foreground">Step-by-step hunting guides for specific threat actors</p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> New Playbook
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Hunt Playbook</DialogTitle>
              <DialogDescription>Create a step-by-step threat hunting guide</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Playbook name" />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What does this playbook cover?"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Threat Actor</Label>
                  <Input
                    value={threatActor}
                    onChange={(e) => setThreatActor(e.target.value)}
                    placeholder="APT29, FIN7, Lazarus..."
                  />
                </div>
                <div>
                  <Label>Difficulty</Label>
                  <Select value={difficulty} onValueChange={setDifficulty}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="beginner">Beginner</SelectItem>
                      <SelectItem value="intermediate">Intermediate</SelectItem>
                      <SelectItem value="advanced">Advanced</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() =>
                  createMutation.mutate({ name, description, threatActor, difficulty, steps: [], mitreTechniques: [] })
                }
                disabled={!name || createMutation.isPending}
              >
                Create Playbook
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : playbooks.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <BookOpen className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-muted-foreground">No playbooks yet. Create step-by-step hunting guides for your team.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {playbooks.map((pb) => (
            <Card
              key={pb.id}
              className="hover:border-primary/30 transition-colors cursor-pointer"
              onClick={() => setSelectedPlaybook(pb)}
            >
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">{pb.name}</CardTitle>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteMutation.mutate(pb.id);
                    }}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="h-3 w-3 text-destructive" />
                  </Button>
                </div>
                <CardDescription className="text-xs">{pb.description || "No description"}</CardDescription>
              </CardHeader>
              <CardContent className="pb-3">
                <div className="flex items-center gap-2 text-xs">
                  {pb.threatActor && (
                    <Badge variant="outline" className="text-[10px]">
                      {pb.threatActor}
                    </Badge>
                  )}
                  {pb.difficulty && (
                    <Badge variant="secondary" className="text-[10px]">
                      {pb.difficulty}
                    </Badge>
                  )}
                  {pb.estimatedTimeMin && (
                    <span className="text-muted-foreground">
                      <Clock className="h-3 w-3 inline mr-1" />
                      {pb.estimatedTimeMin}min
                    </span>
                  )}
                  <span className="text-muted-foreground ml-auto">{(pb.steps as unknown[]).length} steps</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Playbook Detail Dialog */}
      <Dialog open={!!selectedPlaybook} onOpenChange={(o) => !o && setSelectedPlaybook(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          {selectedPlaybook && (
            <>
              <DialogHeader>
                <DialogTitle>{selectedPlaybook.name}</DialogTitle>
                <DialogDescription>{selectedPlaybook.description}</DialogDescription>
              </DialogHeader>
              <div className="flex items-center gap-2 text-xs">
                {selectedPlaybook.threatActor && <Badge variant="outline">{selectedPlaybook.threatActor}</Badge>}
                {selectedPlaybook.difficulty && <Badge variant="secondary">{selectedPlaybook.difficulty}</Badge>}
              </div>
              {(selectedPlaybook.steps as unknown[]).length > 0 ? (
                <div className="space-y-3">
                  {(
                    selectedPlaybook.steps as {
                      order: number;
                      title: string;
                      description: string;
                      queryType: string;
                      queryText: string;
                      expectedOutcome: string;
                    }[]
                  ).map((step, i) => (
                    <div key={i} className="flex gap-3 p-3 bg-muted/30 rounded">
                      <div className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/10 flex items-center justify-center text-xs font-bold text-primary">
                        {step.order || i + 1}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{step.title}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{step.description}</p>
                        {step.queryText && (
                          <pre className="mt-1 text-[10px] font-mono p-1.5 bg-muted/50 rounded">{step.queryText}</pre>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No steps defined yet.</p>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── MITRE ATT&CK Navigator Tab ────────────────────────────────────────────

function MitreNavigatorTab() {
  const { data: coverageData, isLoading } = useQuery<{ coverage: MitreCoverage; totalHunts: number }>({
    queryKey: ["/api/threat-hunting/mitre-coverage"],
  });

  const coverage = coverageData?.coverage || {};

  function getCellColor(techniqueId: string): string {
    const c = coverage[techniqueId];
    if (!c) return "bg-zinc-800/50 hover:bg-zinc-700/50";
    if (c.huntCount >= 3) return "bg-emerald-600/40 hover:bg-emerald-600/60";
    if (c.huntCount >= 2) return "bg-emerald-500/30 hover:bg-emerald-500/50";
    return "bg-cyan-500/20 hover:bg-cyan-500/40";
  }

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">MITRE ATT&CK Navigator</h3>
        <p className="text-sm text-muted-foreground">Visualize your hunting coverage across the ATT&CK framework</p>
      </div>

      <div className="flex items-center gap-6 text-xs">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded bg-zinc-800/50 border border-zinc-700" />
          <span className="text-muted-foreground">No coverage</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded bg-cyan-500/20 border border-cyan-500/30" />
          <span className="text-muted-foreground">1 hunt</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded bg-emerald-500/30 border border-emerald-500/40" />
          <span className="text-muted-foreground">2 hunts</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded bg-emerald-600/40 border border-emerald-600/50" />
          <span className="text-muted-foreground">3+ hunts</span>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <div className="grid grid-cols-1 gap-3">
            {MITRE_TACTICS.map((tactic) => (
              <div key={tactic.id} className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-[10px]">
                    {tactic.id}
                  </Badge>
                  <span className="text-xs font-medium">{tactic.name}</span>
                  <span className="text-[10px] text-muted-foreground">
                    ({tactic.techniques.filter((t) => coverage[t]).length}/{tactic.techniques.length} covered)
                  </span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {tactic.techniques.map((tech) => {
                    const c = coverage[tech];
                    return (
                      <div
                        key={tech}
                        className={`px-2 py-1 rounded text-[10px] font-mono border border-transparent cursor-default transition-colors ${getCellColor(tech)}`}
                        title={
                          c
                            ? `${tech}: ${c.huntCount} hunt(s) — ${c.huntNames.join(", ")}\nLast run: ${c.lastRun || "Never"}`
                            : `${tech}: No coverage`
                        }
                      >
                        {tech}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── 16.1 Enhanced Query Editor with Syntax Highlighting ────────────────────
// (Integrated into QueryBuilderTab — adds line numbers, keyword highlighting,
//  auto-complete suggestions panel, and error marker display)

function SyntaxHighlightedEditor({
  value,
  onChange,
  queryType,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  queryType: string;
  placeholder?: string;
}) {
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [cursorWord, setCursorWord] = useState("");

  const KEYWORDS: Record<string, string[]> = {
    sigma: [
      "title",
      "description",
      "logsource",
      "category",
      "product",
      "detection",
      "selection",
      "condition",
      "level",
      "status",
      "fields",
      "falsepositives",
    ],
    yara: [
      "rule",
      "strings",
      "condition",
      "meta",
      "nocase",
      "wide",
      "ascii",
      "fullword",
      "any",
      "all",
      "of",
      "them",
      "filesize",
      "entrypoint",
    ],
    kql: [
      "where",
      "project",
      "extend",
      "summarize",
      "count",
      "sort",
      "by",
      "top",
      "render",
      "join",
      "union",
      "let",
      "contains",
      "has",
      "startswith",
      "endswith",
      "matches",
      "regex",
    ],
    sql: [
      "SELECT",
      "FROM",
      "WHERE",
      "AND",
      "OR",
      "NOT",
      "IN",
      "LIKE",
      "ORDER",
      "BY",
      "GROUP",
      "HAVING",
      "LIMIT",
      "OFFSET",
      "JOIN",
      "LEFT",
      "RIGHT",
      "INNER",
      "INSERT",
      "UPDATE",
      "DELETE",
      "COUNT",
      "SUM",
      "AVG",
      "MAX",
      "MIN",
      "DISTINCT",
      "AS",
      "ON",
      "DESC",
      "ASC",
    ],
    custom: [],
  };

  const keywords = KEYWORDS[queryType] || [];
  const lines = value.split("\n");

  const filteredSuggestions =
    cursorWord.length >= 1
      ? keywords.filter((k) => k.toLowerCase().startsWith(cursorWord.toLowerCase())).slice(0, 8)
      : [];

  function highlightLine(line: string): string {
    // Simple keyword detection for display purposes
    let highlighted = line;
    for (const kw of keywords) {
      const regex = new RegExp(`\\b(${kw})\\b`, "gi");
      highlighted = highlighted.replace(regex, `**$1**`);
    }
    return highlighted;
  }

  const errors: { line: number; message: string }[] = [];
  // Basic error detection
  if (queryType === "sigma" && value.trim() && !value.includes("detection") && !value.includes("condition")) {
    errors.push({ line: 1, message: "Sigma rules should include a 'detection' section" });
  }
  if (queryType === "yara" && value.trim() && !value.includes("condition")) {
    errors.push({ line: 1, message: "YARA rules must include a 'condition' block" });
  }
  if (
    queryType === "sql" &&
    value.trim() &&
    !value.toUpperCase().includes("SELECT") &&
    !value.toUpperCase().includes("INSERT")
  ) {
    errors.push({ line: 1, message: "SQL query should start with SELECT, INSERT, UPDATE, or DELETE" });
  }

  return (
    <div className="relative">
      <div className="flex border rounded-md bg-muted/20 overflow-hidden">
        {/* Line numbers gutter */}
        <div className="flex-shrink-0 w-10 bg-muted/40 border-r text-right py-2 select-none">
          {lines.map((_, i) => (
            <div
              key={i}
              className={`px-1.5 text-[10px] font-mono leading-5 ${
                errors.some((e) => e.line === i + 1) ? "text-red-400 font-bold" : "text-muted-foreground"
              }`}
            >
              {i + 1}
            </div>
          ))}
        </div>
        {/* Editor area */}
        <div className="flex-1 relative">
          <textarea
            value={value}
            onChange={(e) => {
              onChange(e.target.value);
              // Track cursor word for autocomplete
              const text = e.target.value;
              const pos = e.target.selectionStart;
              const before = text.substring(0, pos);
              const match = before.match(/[a-zA-Z_]+$/);
              setCursorWord(match ? match[0] : "");
              setShowSuggestions(!!match && match[0].length >= 1);
            }}
            onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
            onFocus={() => cursorWord.length >= 1 && setShowSuggestions(true)}
            placeholder={placeholder}
            className="w-full min-h-48 p-2 font-mono text-xs leading-5 bg-transparent resize-y focus:outline-none"
            spellCheck={false}
          />
        </div>
      </div>

      {/* Autocomplete suggestions */}
      {showSuggestions && filteredSuggestions.length > 0 && (
        <div className="absolute z-50 top-full left-10 mt-1 bg-popover border rounded-md shadow-lg max-w-xs">
          {filteredSuggestions.map((s) => (
            <button
              key={s}
              className="block w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-muted/50 transition-colors"
              onMouseDown={(e) => {
                e.preventDefault();
                const suffix = s.substring(cursorWord.length);
                onChange(value + suffix + " ");
                setShowSuggestions(false);
              }}
            >
              <Code className="h-3 w-3 inline mr-1.5 text-cyan-400" />
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Error markers */}
      {errors.length > 0 && (
        <div className="mt-1 space-y-0.5">
          {errors.map((e, i) => (
            <div key={i} className="flex items-center gap-1.5 text-[10px] text-red-400">
              <XCircle className="h-3 w-3" />
              <span>
                Line {e.line}: {e.message}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Language indicator */}
      <div className="absolute top-1 right-2 text-[9px] font-mono text-muted-foreground/50 uppercase">{queryType}</div>
    </div>
  );
}

// ─── 16.3 Hunt Notebook Tab ─────────────────────────────────────────────────

function NotebookTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedNotebook, setSelectedNotebook] = useState<HuntNotebook | null>(null);
  const [newStepTitle, setNewStepTitle] = useState("");
  const [newStepQueryType, setNewStepQueryType] = useState("sigma");
  const [newStepQuery, setNewStepQuery] = useState("");
  const [newStepNotes, setNewStepNotes] = useState("");
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set());

  const { data: notebooksData, isLoading } = useQuery<{ notebooks: HuntNotebook[] }>({
    queryKey: ["/api/threat-hunting/notebooks"],
  });

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/notebooks", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/notebooks"] });
      toast({ title: "Notebook created" });
      setCreateOpen(false);
      setName("");
      setDescription("");
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      apiRequest("PUT", `/api/threat-hunting/notebooks/${id}`, data).then((r) => r.json()),
    onSuccess: (resp: { notebook: HuntNotebook }) => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/notebooks"] });
      setSelectedNotebook(resp.notebook);
      toast({ title: "Notebook updated" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const executeStepMutation = useMutation({
    mutationFn: ({
      notebookId,
      stepIndex,
      queryType,
      queryText,
    }: {
      notebookId: string;
      stepIndex: number;
      queryType: string;
      queryText: string;
    }) =>
      apiRequest("POST", `/api/threat-hunting/notebooks/${notebookId}/execute-step`, {
        stepIndex,
        queryType,
        queryText,
      }).then((r) => r.json()),
    onSuccess: (data: { result: { eventCount: number; executionDurationMs: number }; stepIndex: number }) => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/notebooks"] });
      toast({
        title: `Step executed: ${data.result.eventCount} events in ${formatDuration(data.result.executionDurationMs)}`,
      });
    },
    onError: (e: Error) => toast({ title: "Execution failed", description: e.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/threat-hunting/notebooks/${id}`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/notebooks"] });
      setSelectedNotebook(null);
      toast({ title: "Notebook deleted" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const notebooks = notebooksData?.notebooks || [];

  function addStep() {
    if (!selectedNotebook || !newStepTitle) return;
    const steps = [
      ...selectedNotebook.steps,
      {
        id: crypto.randomUUID(),
        title: newStepTitle,
        queryType: newStepQueryType,
        queryText: newStepQuery,
        notes: newStepNotes,
        resultSummary: null,
        eventCount: null,
        lastExecutedAt: null,
        outputVariables: {},
      },
    ];
    updateMutation.mutate({ id: selectedNotebook.id, data: { steps } });
    setNewStepTitle("");
    setNewStepQuery("");
    setNewStepNotes("");
  }

  function toggleStep(idx: number) {
    const next = new Set(expandedSteps);
    if (next.has(idx)) next.delete(idx);
    else next.add(idx);
    setExpandedSteps(next);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Hunt Notebooks</h3>
          <p className="text-sm text-muted-foreground">
            Multi-step chained investigations — each step&apos;s output feeds the next
          </p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> New Notebook
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Hunt Notebook</DialogTitle>
              <DialogDescription>Build a multi-step investigation workflow</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Investigation name" />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What are you investigating?"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate({ name, description, steps: [] })}
                disabled={!name || createMutation.isPending}
              >
                Create
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Notebook list */}
        <div className="space-y-2">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : notebooks.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center">
                <Notebook className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">No notebooks yet</p>
              </CardContent>
            </Card>
          ) : (
            notebooks.map((nb) => (
              <Card
                key={nb.id}
                className={`cursor-pointer transition-colors ${selectedNotebook?.id === nb.id ? "border-primary" : "hover:border-primary/30"}`}
                onClick={() => setSelectedNotebook(nb)}
              >
                <CardContent className="py-3 px-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">{nb.name}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {nb.steps.length} step(s) &middot; {formatDate(nb.updatedAt)}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteMutation.mutate(nb.id);
                      }}
                    >
                      <Trash2 className="h-3 w-3 text-destructive" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Notebook detail / steps */}
        <div className="lg:col-span-2 space-y-3">
          {!selectedNotebook ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Notebook className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
                <p className="text-muted-foreground">Select a notebook to view its investigation steps</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-semibold">{selectedNotebook.name}</h4>
                  <p className="text-xs text-muted-foreground">{selectedNotebook.description || "No description"}</p>
                </div>
                <Badge variant="outline" className="text-xs">
                  {selectedNotebook.steps.length} steps
                </Badge>
              </div>

              {/* Existing steps */}
              {selectedNotebook.steps.map((step, idx) => (
                <Card key={step.id || idx} className="overflow-hidden">
                  <div
                    className="flex items-center gap-3 px-4 py-2 cursor-pointer hover:bg-muted/30"
                    onClick={() => toggleStep(idx)}
                  >
                    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/10 flex items-center justify-center text-xs font-bold text-primary">
                      {idx + 1}
                    </div>
                    {expandedSteps.has(idx) ? (
                      <ChevronDown className="h-3 w-3 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-3 w-3 text-muted-foreground" />
                    )}
                    <span className="text-sm font-medium flex-1">{step.title}</span>
                    <Badge variant="secondary" className="text-[10px]">
                      {step.queryType}
                    </Badge>
                    {step.resultSummary && (
                      <Badge
                        variant="outline"
                        className={`text-[10px] ${step.eventCount && step.eventCount > 0 ? "text-amber-400 border-amber-500/30" : "text-emerald-400 border-emerald-500/30"}`}
                      >
                        {step.resultSummary}
                      </Badge>
                    )}
                  </div>
                  {expandedSteps.has(idx) && (
                    <div className="px-4 pb-3 space-y-2 border-t bg-muted/10">
                      {step.notes && <p className="text-xs text-muted-foreground mt-2">{step.notes}</p>}
                      <pre className="text-[10px] font-mono p-2 bg-muted/30 rounded max-h-32 overflow-auto whitespace-pre-wrap">
                        {step.queryText || "No query defined"}
                      </pre>
                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs"
                          onClick={() =>
                            executeStepMutation.mutate({
                              notebookId: selectedNotebook.id,
                              stepIndex: idx,
                              queryType: step.queryType,
                              queryText: step.queryText,
                            })
                          }
                          disabled={executeStepMutation.isPending || !step.queryText}
                        >
                          {executeStepMutation.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin mr-1" />
                          ) : (
                            <Play className="h-3 w-3 mr-1" />
                          )}
                          Run Step
                        </Button>
                        {step.lastExecutedAt && (
                          <span className="text-[10px] text-muted-foreground">
                            Last run: {formatDate(step.lastExecutedAt)}
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </Card>
              ))}

              {/* Add new step */}
              <Card className="border-dashed">
                <CardContent className="py-3 px-4 space-y-3">
                  <p className="text-xs font-medium text-muted-foreground">Add Investigation Step</p>
                  <div className="grid grid-cols-2 gap-3">
                    <Input
                      value={newStepTitle}
                      onChange={(e) => setNewStepTitle(e.target.value)}
                      placeholder="Step title"
                      className="text-xs"
                    />
                    <Select value={newStepQueryType} onValueChange={setNewStepQueryType}>
                      <SelectTrigger className="text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="sigma">Sigma</SelectItem>
                        <SelectItem value="yara">YARA</SelectItem>
                        <SelectItem value="kql">KQL</SelectItem>
                        <SelectItem value="sql">SQL</SelectItem>
                        <SelectItem value="custom">Custom</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Textarea
                    value={newStepQuery}
                    onChange={(e) => setNewStepQuery(e.target.value)}
                    placeholder="Query for this step..."
                    className="font-mono text-xs min-h-20"
                  />
                  <Input
                    value={newStepNotes}
                    onChange={(e) => setNewStepNotes(e.target.value)}
                    placeholder="Notes / context for this step"
                    className="text-xs"
                  />
                  <Button
                    size="sm"
                    onClick={addStep}
                    disabled={!newStepTitle || updateMutation.isPending}
                    className="w-full"
                  >
                    <Plus className="h-3 w-3 mr-1" /> Add Step
                  </Button>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── 16.2 Result Visualization Options ──────────────────────────────────────

function ResultVisualizationPanel({ results }: { results: HuntResult[] }) {
  const [viewMode, setViewMode] = useState<"table" | "timeline" | "chart">("table");

  if (results.length === 0) return null;

  const allEvents = results.flatMap((r) =>
    Array.isArray(r.eventsJson) ? (r.eventsJson as Record<string, unknown>[]) : [],
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">View:</span>
        <div className="flex bg-muted/30 rounded p-0.5 gap-0.5">
          {(["table", "timeline", "chart"] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                viewMode === mode
                  ? "bg-background shadow text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {mode === "table" && (
                <>
                  <Layers className="h-3 w-3 inline mr-1" />
                  Table
                </>
              )}
              {mode === "timeline" && (
                <>
                  <Clock className="h-3 w-3 inline mr-1" />
                  Timeline
                </>
              )}
              {mode === "chart" && (
                <>
                  <BarChart3 className="h-3 w-3 inline mr-1" />
                  Chart
                </>
              )}
            </button>
          ))}
        </div>
        <Badge variant="outline" className="text-[10px] ml-auto">
          {allEvents.length} events across {results.length} run(s)
        </Badge>
      </div>

      {viewMode === "table" && (
        <div className="border rounded-md overflow-auto max-h-64">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs w-12">#</TableHead>
                <TableHead className="text-xs">Event Data</TableHead>
                <TableHead className="text-xs w-36">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {allEvents.slice(0, 50).map((evt, i) => (
                <TableRow key={i}>
                  <TableCell className="text-xs font-mono">{i + 1}</TableCell>
                  <TableCell className="text-xs font-mono max-w-md truncate">
                    {JSON.stringify(evt).substring(0, 200)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {(evt as Record<string, unknown>).timestamp
                      ? String((evt as Record<string, unknown>).timestamp)
                      : "-"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {viewMode === "timeline" && (
        <div className="space-y-1 max-h-64 overflow-auto">
          {results.map((r, idx) => (
            <div key={r.id} className="flex items-center gap-3 py-1.5 border-b last:border-0">
              <div className="flex-shrink-0 w-2 h-2 rounded-full bg-primary" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium">Run #{idx + 1}</span>
                  <Badge variant={r.eventCount > 0 ? "default" : "secondary"} className="text-[10px]">
                    {r.eventCount} events
                  </Badge>
                  {r.executionDurationMs && (
                    <span className="text-[10px] text-muted-foreground">{formatDuration(r.executionDurationMs)}</span>
                  )}
                </div>
                {r.summary && <p className="text-[10px] text-muted-foreground truncate mt-0.5">{r.summary}</p>}
              </div>
              <span className="text-[10px] text-muted-foreground flex-shrink-0">{formatDate(r.executedAt)}</span>
            </div>
          ))}
        </div>
      )}

      {viewMode === "chart" && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">Event Count by Execution</p>
          <div className="flex items-end gap-1 h-32">
            {results.slice(-20).map((r, i) => {
              const maxCount = Math.max(...results.map((x) => x.eventCount), 1);
              const height = Math.max((r.eventCount / maxCount) * 100, 4);
              return (
                <TooltipProvider key={r.id}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div
                        className="flex-1 min-w-[8px] bg-primary/60 hover:bg-primary/80 rounded-t transition-colors cursor-pointer"
                        style={{ height: `${height}%` }}
                      />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p className="text-xs">
                        Run #{i + 1}: {r.eventCount} events
                      </p>
                      <p className="text-[10px] text-muted-foreground">{formatDate(r.executedAt)}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              );
            })}
          </div>
          <div className="flex justify-between text-[10px] text-muted-foreground">
            <span>Oldest</span>
            <span>Most Recent</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── 16.5 Query Execution Plan Display ──────────────────────────────────────

function ExecutionPlanPanel({ huntId }: { huntId: string }) {
  const { toast } = useToast();
  const [plan, setPlan] = useState<ExecutionPlan | null>(null);
  const [loading, setLoading] = useState(false);

  async function fetchPlan() {
    setLoading(true);
    try {
      const resp = await apiRequest("POST", `/api/threat-hunting/hunts/${huntId}/execution-plan`);
      const data = await resp.json();
      setPlan(data.plan);
    } catch (e) {
      toast({ title: "Error", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium">Execution Plan</span>
        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={fetchPlan} disabled={loading}>
          {loading ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Zap className="h-3 w-3 mr-1" />}
          Analyze Query
        </Button>
      </div>

      {plan && (
        <div className="space-y-3">
          {/* Summary metrics */}
          <div className="grid grid-cols-3 gap-2">
            <div className="bg-muted/20 rounded p-2 text-center">
              <p className="text-lg font-bold">{plan.estimatedRows.toLocaleString()}</p>
              <p className="text-[10px] text-muted-foreground">Est. Rows</p>
            </div>
            <div className="bg-muted/20 rounded p-2 text-center">
              <p className="text-lg font-bold">{formatDuration(plan.estimatedTimeMs)}</p>
              <p className="text-[10px] text-muted-foreground">Est. Time</p>
            </div>
            <div className="bg-muted/20 rounded p-2 text-center">
              <p className="text-lg font-bold">{plan.dataSources.length}</p>
              <p className="text-[10px] text-muted-foreground">Data Sources</p>
            </div>
          </div>

          {/* Execution steps */}
          <div className="space-y-1">
            <p className="text-[10px] font-medium text-muted-foreground uppercase">Pipeline</p>
            {plan.steps.map((step, i) => (
              <div key={i} className="flex items-center gap-2 text-xs py-1">
                <div className="w-5 h-5 rounded-full bg-primary/10 flex items-center justify-center text-[10px] font-bold text-primary flex-shrink-0">
                  {i + 1}
                </div>
                <span className="flex-1">{step.description}</span>
                <Badge variant="outline" className="text-[10px]">
                  {step.estimatedMs}ms
                </Badge>
              </div>
            ))}
          </div>

          {/* Optimizations */}
          {plan.optimizations.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] font-medium text-emerald-400">Optimizations Applied</p>
              {plan.optimizations.map((o, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs">
                  <CheckCircle2 className="h-3 w-3 text-green-500" />
                  <span>{o}</span>
                </div>
              ))}
            </div>
          )}

          {/* Warnings */}
          {plan.warnings.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] font-medium text-amber-400">Warnings</p>
              {plan.warnings.map((w, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs">
                  <AlertTriangle className="h-3 w-3 text-amber-400" />
                  <span>{w}</span>
                </div>
              ))}
            </div>
          )}

          {/* Data sources */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-muted-foreground">Sources:</span>
            {plan.dataSources.map((ds) => (
              <Badge key={ds} variant="secondary" className="text-[10px]">
                <Database className="h-2.5 w-2.5 mr-1" />
                {ds}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── 16.6 Hunt Result Cache Tab ─────────────────────────────────────────────

function CacheTab() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: cacheData, isLoading } = useQuery<{ entries: CacheEntry[] }>({
    queryKey: ["/api/threat-hunting/cache"],
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/threat-hunting/cache/${id}`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/cache"] });
      toast({ title: "Cache entry deleted" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const clearMutation = useMutation({
    mutationFn: () => apiRequest("DELETE", "/api/threat-hunting/cache").then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/cache"] });
      toast({ title: "All cache entries cleared" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const entries = cacheData?.entries || [];
  const activeEntries = entries.filter((e) => !e.isExpired);
  const totalHits = entries.reduce((s, e) => s + e.hitCount, 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Result Cache</h3>
          <p className="text-sm text-muted-foreground">
            Cached hunt results with TTL — avoid re-running expensive queries
          </p>
        </div>
        <Button
          size="sm"
          variant="destructive"
          onClick={() => clearMutation.mutate()}
          disabled={clearMutation.isPending || entries.length === 0}
        >
          <Trash2 className="h-4 w-4 mr-1" /> Clear All
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-cyan-400" />
              <span className="text-xs text-muted-foreground">Cached Entries</span>
            </div>
            <p className="text-2xl font-bold mt-1">{activeEntries.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Eye className="h-4 w-4 text-emerald-400" />
              <span className="text-xs text-muted-foreground">Total Hits</span>
            </div>
            <p className="text-2xl font-bold mt-1">{totalHits}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Timer className="h-4 w-4 text-amber-400" />
              <span className="text-xs text-muted-foreground">Expired</span>
            </div>
            <p className="text-2xl font-bold mt-1">{entries.length - activeEntries.length}</p>
          </CardContent>
        </Card>
      </div>

      {/* Cache entries */}
      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      ) : entries.length === 0 ? (
        <EmptyState
          icon={Database}
          title="No cached results"
          description="Run hunts to populate the cache automatically"
        />
      ) : (
        <div className="space-y-2">
          {entries.map((entry) => (
            <Card key={entry.id} className={entry.isExpired ? "opacity-50" : ""}>
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-[10px]">
                        {entry.queryType}
                      </Badge>
                      <span className="text-xs font-mono truncate">{entry.queryText.substring(0, 80)}</span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                      <span>{entry.eventCount} events</span>
                      <span>{entry.hitCount} hit(s)</span>
                      <span>TTL: {entry.ttlSeconds}s</span>
                      <span>Cached: {formatDate(entry.cachedAt)}</span>
                      {entry.isExpired ? (
                        <Badge variant="destructive" className="text-[10px]">
                          Expired
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-500/30">
                          Active
                        </Badge>
                      )}
                    </div>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => deleteMutation.mutate(entry.id)}>
                    <Trash2 className="h-3 w-3 text-destructive" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── 16.7 Drift Detection Alerts ────────────────────────────────────────────

function DriftDetectionPanel() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: driftData, isLoading } = useQuery<{ drifts: DriftEntry[] }>({
    queryKey: ["/api/threat-hunting/drifts"],
  });

  const ackMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("PATCH", `/api/threat-hunting/drifts/${id}/acknowledge`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/drifts"] });
      toast({ title: "Drift acknowledged" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const drifts = driftData?.drifts || [];
  const unacknowledged = drifts.filter((d) => !d.drift.acknowledged);
  const significant = drifts.filter((d) => d.drift.isSignificant);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Drift Detection</h3>
          <p className="text-sm text-muted-foreground">Monitor scheduled hunt results for significant changes</p>
        </div>
        {unacknowledged.length > 0 && (
          <Badge variant="destructive" className="text-xs">
            {unacknowledged.length} unacknowledged
          </Badge>
        )}
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-cyan-400" />
              <span className="text-xs text-muted-foreground">Total Drifts</span>
            </div>
            <p className="text-2xl font-bold mt-1">{drifts.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              <span className="text-xs text-muted-foreground">Significant</span>
            </div>
            <p className="text-2xl font-bold mt-1">{significant.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Eye className="h-4 w-4 text-amber-400" />
              <span className="text-xs text-muted-foreground">Pending Review</span>
            </div>
            <p className="text-2xl font-bold mt-1">{unacknowledged.length}</p>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      ) : drifts.length === 0 ? (
        <EmptyState
          icon={TrendingUp}
          title="No drift detected"
          description="Schedule hunts to begin tracking result changes over time"
        />
      ) : (
        <div className="space-y-2">
          {drifts.map(({ drift, huntName }) => (
            <Card key={drift.id} className={!drift.acknowledged && drift.isSignificant ? "border-red-500/30" : ""}>
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      {drift.driftDirection === "increase" ? (
                        <TrendingUp className="h-4 w-4 text-red-400" />
                      ) : drift.driftDirection === "decrease" ? (
                        <TrendingDown className="h-4 w-4 text-emerald-400" />
                      ) : (
                        <Minus className="h-4 w-4 text-muted-foreground" />
                      )}
                      <span className="text-sm font-medium">{huntName || "Unknown Hunt"}</span>
                      <Badge variant={drift.isSignificant ? "destructive" : "secondary"} className="text-[10px]">
                        {drift.driftDirection === "increase" ? "+" : drift.driftDirection === "decrease" ? "-" : ""}
                        {drift.driftPercentage}%
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                      <span>Previous: {drift.previousEventCount} events</span>
                      <ArrowRight className="h-2.5 w-2.5" />
                      <span>Current: {drift.currentEventCount} events</span>
                      <span>&middot; {formatDate(drift.detectedAt)}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {drift.acknowledged ? (
                      <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-500/30">
                        Acknowledged
                      </Badge>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => ackMutation.mutate(drift.id)}
                        disabled={ackMutation.isPending}
                      >
                        <CheckCircle2 className="h-3 w-3 text-green-500" /> Acknowledge
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── 16.4 Collaborative Hunting Tab ─────────────────────────────────────────

function CollaborationTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [sessionName, setSessionName] = useState("");
  const [selectedHuntId, setSelectedHuntId] = useState("");
  const [selectedSession, setSelectedSession] = useState<CollaborationSession | null>(null);
  const [chatMessage, setChatMessage] = useState("");

  const { data: sessionsData, isLoading } = useQuery<{ sessions: CollaborationSession[] }>({
    queryKey: ["/api/threat-hunting/collaborations"],
  });

  const { data: huntsData } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/collaborations", data).then((r) => r.json()),
    onSuccess: (resp: { session: CollaborationSession }) => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/collaborations"] });
      toast({ title: "Collaboration session created" });
      setSelectedSession(resp.session);
      setCreateOpen(false);
      setSessionName("");
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const joinMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/threat-hunting/collaborations/${id}/join`).then((r) => r.json()),
    onSuccess: (resp: { session: CollaborationSession }) => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/collaborations"] });
      setSelectedSession(resp.session);
      toast({ title: "Joined session" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const messageMutation = useMutation({
    mutationFn: ({ id, message }: { id: string; message: string }) =>
      apiRequest("POST", `/api/threat-hunting/collaborations/${id}/message`, { message }).then((r) => r.json()),
    onSuccess: (resp: { session: CollaborationSession }) => {
      setSelectedSession(resp.session);
      setChatMessage("");
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const endMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/threat-hunting/collaborations/${id}/end`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/collaborations"] });
      setSelectedSession(null);
      toast({ title: "Session ended" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const sessions = sessionsData?.sessions || [];
  const hunts = huntsData?.hunts || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Collaborative Hunting</h3>
          <p className="text-sm text-muted-foreground">Hunt together in real-time with shared results and chat</p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Users className="h-4 w-4 mr-1" /> New Session
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Start Collaboration Session</DialogTitle>
              <DialogDescription>Invite your team to hunt together in real-time</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Session Name</Label>
                <Input
                  value={sessionName}
                  onChange={(e) => setSessionName(e.target.value)}
                  placeholder="e.g., APT29 Investigation"
                />
              </div>
              <div>
                <Label>Link to Hunt (optional)</Label>
                <Select value={selectedHuntId} onValueChange={setSelectedHuntId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a hunt..." />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No specific hunt</SelectItem>
                    {hunts.map((h) => (
                      <SelectItem key={h.id} value={h.id}>
                        {h.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() =>
                  createMutation.mutate({
                    sessionName,
                    huntId: selectedHuntId === "none" ? null : selectedHuntId || null,
                  })
                }
                disabled={!sessionName || createMutation.isPending}
              >
                Start Session
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Sessions list */}
        <div className="space-y-2">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : sessions.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center">
                <Users className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">No collaboration sessions</p>
              </CardContent>
            </Card>
          ) : (
            sessions.map((s) => (
              <Card
                key={s.id}
                className={`cursor-pointer transition-colors ${selectedSession?.id === s.id ? "border-primary" : "hover:border-primary/30"}`}
                onClick={() => setSelectedSession(s)}
              >
                <CardContent className="py-3 px-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">{s.sessionName}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant={s.status === "active" ? "default" : "secondary"} className="text-[10px]">
                          {s.status}
                        </Badge>
                        <span className="text-[10px] text-muted-foreground">
                          {s.participants.length} participant(s)
                        </span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Session detail */}
        <div className="lg:col-span-2 space-y-3">
          {!selectedSession ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Users className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
                <p className="text-muted-foreground">Select a session to collaborate</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-semibold">{selectedSession.sessionName}</h4>
                  <p className="text-xs text-muted-foreground">Started {formatDate(selectedSession.startedAt)}</p>
                </div>
                <div className="flex items-center gap-2">
                  {selectedSession.status === "active" && (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => joinMutation.mutate(selectedSession.id)}
                        disabled={joinMutation.isPending}
                      >
                        <Users className="h-3 w-3 mr-1" /> Join
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        className="h-7 text-xs"
                        onClick={() => endMutation.mutate(selectedSession.id)}
                        disabled={endMutation.isPending}
                      >
                        <StopCircle className="h-3 w-3 mr-1" /> End
                      </Button>
                    </>
                  )}
                </div>
              </div>

              {/* Participants */}
              <div className="flex items-center gap-2 flex-wrap">
                {selectedSession.participants.map((p, i) => (
                  <div key={i} className="flex items-center gap-1.5 px-2 py-1 bg-muted/30 rounded-full text-xs">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
                    <span>{p.name}</span>
                  </div>
                ))}
              </div>

              {/* Chat */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-1.5">
                    <MessageSquare className="h-4 w-4" /> Team Chat
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-48 mb-3">
                    {selectedSession.chatMessages.length === 0 ? (
                      <p className="text-xs text-muted-foreground text-center py-4">No messages yet</p>
                    ) : (
                      <div className="space-y-2">
                        {selectedSession.chatMessages.map((msg, i) => (
                          <div key={i} className="text-xs">
                            <span className="font-medium">{msg.name}</span>
                            <span className="text-muted-foreground ml-2">
                              {new Date(msg.timestamp).toLocaleTimeString()}
                            </span>
                            <p className="mt-0.5">{msg.message}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </ScrollArea>
                  {selectedSession.status === "active" && (
                    <div className="flex items-center gap-2">
                      <Input
                        value={chatMessage}
                        onChange={(e) => setChatMessage(e.target.value)}
                        placeholder="Type a message..."
                        className="text-xs"
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && chatMessage.trim()) {
                            messageMutation.mutate({ id: selectedSession.id, message: chatMessage });
                          }
                        }}
                      />
                      <Button
                        size="sm"
                        onClick={() =>
                          chatMessage.trim() && messageMutation.mutate({ id: selectedSession.id, message: chatMessage })
                        }
                        disabled={!chatMessage.trim() || messageMutation.isPending}
                      >
                        <Send className="h-3 w-3" />
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── 16.8 Hunt → Incident Escalation Button ────────────────────────────────

function EscalateHuntButton({ huntId, huntName }: { huntId: string; huntName: string }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const escalateMutation = useMutation({
    mutationFn: () => apiRequest("POST", `/api/threat-hunting/hunts/${huntId}/escalate-incident`).then((r) => r.json()),
    onSuccess: (data: { incident: { id: string; title: string; severity: string }; message: string }) => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/hunts"] });
      toast({
        title: "Incident created",
        description: `${data.incident.title} (${data.incident.severity})`,
      });
      setConfirmOpen(false);
    },
    onError: (e: Error) => toast({ title: "Escalation failed", description: e.message, variant: "destructive" }),
  });

  return (
    <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" className="h-7 text-xs">
          <AlertTriangle className="h-3 w-3 mr-1 text-amber-400" /> Escalate
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Escalate to Incident</DialogTitle>
          <DialogDescription>
            Create a new incident from hunt &quot;{huntName}&quot; with all findings, MITRE techniques, and result data
            pre-populated.
          </DialogDescription>
        </DialogHeader>
        <div className="py-4">
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-md p-3 text-sm">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <span className="font-medium text-amber-400">This will create a real incident</span>
            </div>
            <p className="text-xs text-muted-foreground">
              The incident will include the hunt hypothesis, query, results summary, MITRE ATT&CK techniques, and
              matched events. The latest hunt result will be linked to the new incident.
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setConfirmOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => escalateMutation.mutate()} disabled={escalateMutation.isPending}>
            {escalateMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <AlertTriangle className="h-4 w-4 mr-1" />
            )}
            Create Incident
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── 16.9 Hunt → Detection Rule Conversion ──────────────────────────────────

function ConvertToRuleButton({ huntId, huntName }: { huntId: string; huntName: string }) {
  const { toast } = useToast();
  const [ruleOpen, setRuleOpen] = useState(false);
  const [sigmaRule, setSigmaRule] = useState("");

  const convertMutation = useMutation({
    mutationFn: () => apiRequest("POST", `/api/threat-hunting/hunts/${huntId}/to-detection-rule`).then((r) => r.json()),
    onSuccess: (data: { sigmaRule: string }) => {
      setSigmaRule(data.sigmaRule);
      setRuleOpen(true);
    },
    onError: (e: Error) => toast({ title: "Conversion failed", description: e.message, variant: "destructive" }),
  });

  return (
    <>
      <Button
        size="sm"
        variant="outline"
        className="h-7 text-xs"
        onClick={() => convertMutation.mutate()}
        disabled={convertMutation.isPending}
      >
        {convertMutation.isPending ? (
          <Loader2 className="h-3 w-3 animate-spin mr-1" />
        ) : (
          <FileCode className="h-3 w-3 mr-1" />
        )}
        To Sigma Rule
      </Button>

      <Dialog open={ruleOpen} onOpenChange={setRuleOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Generated Sigma Detection Rule</DialogTitle>
            <DialogDescription>Converted from hunt &quot;{huntName}&quot;</DialogDescription>
          </DialogHeader>
          <div className="relative">
            <pre className="bg-muted/30 border rounded-md p-4 text-xs font-mono max-h-96 overflow-auto whitespace-pre-wrap">
              {sigmaRule}
            </pre>
            <Button
              size="sm"
              variant="ghost"
              className="absolute top-2 right-2 h-7 text-xs"
              onClick={() => {
                navigator.clipboard.writeText(sigmaRule);
                toast({ title: "Copied to clipboard" });
              }}
            >
              <Copy className="h-3 w-3 mr-1" /> Copy
            </Button>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── 16.10 Community Hunt Library Tab ───────────────────────────────────────

function CommunityTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [shareOpen, setShareOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("apt");
  const [selectedHuntId, setSelectedHuntId] = useState("");
  const [filter, setFilter] = useState("");

  const { data: communityData, isLoading } = useQuery<{ shares: CommunityShare[] }>({
    queryKey: ["/api/threat-hunting/community", filter],
    queryFn: () =>
      apiRequest("GET", `/api/threat-hunting/community${filter ? `?category=${filter}` : ""}`).then((r) => r.json()),
  });

  const { data: huntsData } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const shareMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/threat-hunting/community", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/community"] });
      toast({ title: "Hunt shared to community" });
      setShareOpen(false);
      setTitle("");
      setDescription("");
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const upvoteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("POST", `/api/threat-hunting/community/${id}/upvote`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/community"] });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const downloadMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/threat-hunting/community/${id}/download`).then((r) => r.json()),
    onSuccess: (data: { queryType: string; queryText: string }) => {
      navigator.clipboard.writeText(data.queryText);
      toast({ title: `${data.queryType.toUpperCase()} query copied to clipboard` });
      qc.invalidateQueries({ queryKey: ["/api/threat-hunting/community"] });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const shares = communityData?.shares || [];
  const hunts = huntsData?.hunts || [];
  const categories = [
    "apt",
    "ransomware",
    "insider_threat",
    "lateral_movement",
    "persistence",
    "exfiltration",
    "credential_access",
    "discovery",
    "other",
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Community Hunt Library</h3>
          <p className="text-sm text-muted-foreground">
            Share and discover threat hunts with anonymized detection statistics
          </p>
        </div>
        <Dialog open={shareOpen} onOpenChange={setShareOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Globe className="h-4 w-4 mr-1" /> Share Hunt
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Share to Community</DialogTitle>
              <DialogDescription>Publish a hunt with anonymized detection stats</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Select Hunt</Label>
                <Select value={selectedHuntId} onValueChange={setSelectedHuntId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a hunt to share..." />
                  </SelectTrigger>
                  <SelectContent>
                    {hunts.map((h) => (
                      <SelectItem key={h.id} value={h.id}>
                        {h.name} ({h.queryType})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Title</Label>
                <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Community-facing title" />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What does this hunt detect?"
                />
              </div>
              <div>
                <Label>Category</Label>
                <Select value={category} onValueChange={setCategory}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {categories.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c.replace(/_/g, " ").replace(/\b[a-z]/g, (l) => l.toUpperCase())}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShareOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => shareMutation.mutate({ huntId: selectedHuntId, title, description, category })}
                disabled={!selectedHuntId || !title || shareMutation.isPending}
              >
                {shareMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                ) : (
                  <Share2 className="h-4 w-4 mr-1" />
                )}
                Publish
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Category filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setFilter("")}
          className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${!filter ? "bg-primary text-primary-foreground" : "hover:bg-muted/50"}`}
        >
          All
        </button>
        {categories.map((c) => (
          <button
            key={c}
            onClick={() => setFilter(c)}
            className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${filter === c ? "bg-primary text-primary-foreground" : "hover:bg-muted/50"}`}
          >
            {c.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      ) : shares.length === 0 ? (
        <EmptyState
          icon={Globe}
          title="No community hunts"
          description="Be the first to share a hunt with the community"
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {shares.map((share) => (
            <Card key={share.id}>
              <CardContent className="py-4 px-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-[10px]">
                      {share.queryType}
                    </Badge>
                    {share.category && (
                      <Badge variant="outline" className="text-[10px]">
                        {share.category.replace(/_/g, " ")}
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-1 text-muted-foreground">
                    <button
                      onClick={() => upvoteMutation.mutate(share.id)}
                      className="flex items-center gap-0.5 hover:text-primary transition-colors"
                    >
                      <ThumbsUp className="h-3 w-3" />
                      <span className="text-[10px]">{share.upvotes}</span>
                    </button>
                    <span className="text-[10px] mx-1">&middot;</span>
                    <span className="text-[10px]">{share.downloads} downloads</span>
                  </div>
                </div>
                <p className="text-sm font-medium">{share.title}</p>
                {share.description && <p className="text-xs text-muted-foreground line-clamp-2">{share.description}</p>}

                {/* Anonymized stats */}
                <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                  <span>Detection rate: {share.anonymizedStats.detectionRate}%</span>
                  <span>Avg exec: {formatDuration(share.anonymizedStats.avgExecutionMs)}</span>
                  <span>{share.anonymizedStats.totalRuns} runs</span>
                </div>

                {/* MITRE techniques */}
                {share.mitreTechniques.length > 0 && (
                  <div className="flex items-center gap-1 flex-wrap">
                    {(share.mitreTechniques as string[]).slice(0, 5).map((t) => (
                      <Badge key={t} variant="outline" className="text-[10px]">
                        {t}
                      </Badge>
                    ))}
                    {share.mitreTechniques.length > 5 && (
                      <span className="text-[10px] text-muted-foreground">
                        +{share.mitreTechniques.length - 5} more
                      </span>
                    )}
                  </div>
                )}

                <Button
                  size="sm"
                  variant="outline"
                  className="w-full h-7 text-xs"
                  onClick={() => downloadMutation.mutate(share.id)}
                  disabled={downloadMutation.isPending}
                >
                  <Download className="h-3 w-3 mr-1" /> Import Query
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function ThreatHuntingPage() {
  const { data: statsData } = useQuery<{
    totalHunts: number;
    totalExecutions: number;
    activeSchedules: number;
    totalPlaybooks: number;
  }>({
    queryKey: ["/api/threat-hunting/stats"],
  });

  const stats = statsData || { totalHunts: 0, totalExecutions: 0, activeSchedules: 0, totalPlaybooks: 0 };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Crosshair className="h-6 w-6 text-cyan-400" />
          Threat Hunting Workbench
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Proactively hunt for threats using Sigma, YARA, KQL queries with AI-driven hypothesis generation
        </p>
      </div>

      <StatsCards stats={stats} />

      <Tabs defaultValue="query-builder">
        <div className="overflow-x-auto">
          <TabsList className="inline-flex w-auto min-w-full">
            <TabsTrigger value="query-builder" className="text-xs">
              <Code className="h-3 w-3 mr-1" /> Query Builder
            </TabsTrigger>
            <TabsTrigger value="notebooks" className="text-xs">
              <Notebook className="h-3 w-3 mr-1" /> Notebooks
            </TabsTrigger>
            <TabsTrigger value="results" className="text-xs">
              <BarChart3 className="h-3 w-3 mr-1" /> Results
            </TabsTrigger>
            <TabsTrigger value="library" className="text-xs">
              <BookOpen className="h-3 w-3 mr-1" /> Library
            </TabsTrigger>
            <TabsTrigger value="schedules" className="text-xs">
              <Calendar className="h-3 w-3 mr-1" /> Schedules
            </TabsTrigger>
            <TabsTrigger value="collaboration" className="text-xs">
              <Users className="h-3 w-3 mr-1" /> Collaborate
            </TabsTrigger>
            <TabsTrigger value="cache" className="text-xs">
              <Database className="h-3 w-3 mr-1" /> Cache
            </TabsTrigger>
            <TabsTrigger value="drift" className="text-xs">
              <TrendingUp className="h-3 w-3 mr-1" /> Drift
            </TabsTrigger>
            <TabsTrigger value="community" className="text-xs">
              <Globe className="h-3 w-3 mr-1" /> Community
            </TabsTrigger>
            <TabsTrigger value="pivot" className="text-xs">
              <Target className="h-3 w-3 mr-1" /> Pivot
            </TabsTrigger>
            <TabsTrigger value="hypotheses" className="text-xs">
              <Brain className="h-3 w-3 mr-1" /> Hypotheses
            </TabsTrigger>
            <TabsTrigger value="playbooks" className="text-xs">
              <FileCode className="h-3 w-3 mr-1" /> Playbooks
            </TabsTrigger>
          </TabsList>
        </div>

        <div className="mt-4">
          <TabsContent value="query-builder">
            <QueryBuilderTab />
          </TabsContent>
          <TabsContent value="notebooks">
            <NotebookTab />
          </TabsContent>
          <TabsContent value="results">
            <HuntResultsTab />
          </TabsContent>
          <TabsContent value="library">
            <HuntLibraryTab />
          </TabsContent>
          <TabsContent value="schedules">
            <HuntSchedulesTab />
          </TabsContent>
          <TabsContent value="collaboration">
            <CollaborationTab />
          </TabsContent>
          <TabsContent value="cache">
            <CacheTab />
          </TabsContent>
          <TabsContent value="drift">
            <DriftDetectionPanel />
          </TabsContent>
          <TabsContent value="community">
            <CommunityTab />
          </TabsContent>
          <TabsContent value="pivot">
            <PivotTab />
          </TabsContent>
          <TabsContent value="hypotheses">
            <HypothesisTab />
          </TabsContent>
          <TabsContent value="playbooks">
            <PlaybooksTab />
          </TabsContent>
        </div>
      </Tabs>

      <Separator />

      {/* MITRE ATT&CK Navigator as a separate section below tabs */}
      <MitreNavigatorTab />
    </div>
  );
}
