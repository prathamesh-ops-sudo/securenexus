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
} from "lucide-react";

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

// ─── Helpers ────────────────────────────────────────────────────────────────

function statusColor(status: string): string {
  switch (status) {
    case "completed":
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    case "running":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    case "failed":
      return "bg-red-500/10 text-red-400 border-red-500/20";
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
  if (!ms) return "-";
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
                <Textarea
                  value={queryText}
                  onChange={(e) => setQueryText(e.target.value)}
                  placeholder={placeholders[queryType] || ""}
                  className="font-mono text-xs min-h-48"
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
          <CardContent className="py-12 text-center">
            <Crosshair className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-muted-foreground">No hunts yet. Create your first threat hunt to get started.</p>
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
                    <CheckCircle2 className="h-3 w-3 text-emerald-400" />
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
  const [selectedHuntId, setSelectedHuntId] = useState<string>("");

  const { data: huntsData } = useQuery<{ hunts: ThreatHunt[] }>({
    queryKey: ["/api/threat-hunting/hunts"],
  });

  const { data: resultsData, isLoading } = useQuery<{ results: HuntResult[] }>({
    queryKey: [`/api/threat-hunting/results/${selectedHuntId}`],
    enabled: !!selectedHuntId,
  });

  const hunts = huntsData?.hunts || [];
  const results = resultsData?.results || [];

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
        <div className="space-y-3">
          {results.map((r) => (
            <Card key={r.id}>
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    {r.eventCount > 0 ? (
                      <AlertTriangle className="h-5 w-5 text-amber-400" />
                    ) : (
                      <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium">{r.eventCount} events matched</p>
                      <p className="text-xs text-muted-foreground">
                        Executed {formatDate(r.executedAt)} in {formatDuration(r.executionDurationMs)}
                      </p>
                    </div>
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
    </div>
  );
}

// ─── Pivot Interface Tab ────────────────────────────────────────────────────

function PivotTab() {
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
            if (e.key === "Enter" && iocValue) pivotMutation.mutate();
          }}
        />
        <Button onClick={() => pivotMutation.mutate()} disabled={!iocValue || pivotMutation.isPending}>
          {pivotMutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Search className="h-4 w-4 mr-1" />
          )}
          Pivot
        </Button>
      </div>

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
                <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-emerald-400" />
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
        <TabsList className="grid grid-cols-7 w-full">
          <TabsTrigger value="query-builder" className="text-xs">
            <Code className="h-3 w-3 mr-1" /> Query Builder
          </TabsTrigger>
          <TabsTrigger value="library" className="text-xs">
            <BookOpen className="h-3 w-3 mr-1" /> Library
          </TabsTrigger>
          <TabsTrigger value="schedules" className="text-xs">
            <Calendar className="h-3 w-3 mr-1" /> Schedules
          </TabsTrigger>
          <TabsTrigger value="results" className="text-xs">
            <BarChart3 className="h-3 w-3 mr-1" /> Results
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

        <div className="mt-4">
          <TabsContent value="query-builder">
            <QueryBuilderTab />
          </TabsContent>
          <TabsContent value="library">
            <HuntLibraryTab />
          </TabsContent>
          <TabsContent value="schedules">
            <HuntSchedulesTab />
          </TabsContent>
          <TabsContent value="results">
            <HuntResultsTab />
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
