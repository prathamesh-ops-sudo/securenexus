import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  ShieldAlert,
  Search,
  Plus,
  Filter,
  ToggleLeft,
  ToggleRight,
  Eye,
  Trash2,
  RefreshCw,
  AlertTriangle,
  Activity,
  Target,
  X,
  ChevronRight,
  Code,
  Clock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-green-500/10 text-green-500 border-green-500/20",
  informational: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  enabled: "bg-green-500/10 text-green-500",
  disabled: "bg-zinc-500/10 text-zinc-500",
  testing: "bg-blue-500/10 text-blue-500",
};

const TACTIC_LABELS: Record<string, string> = {
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege Escalation",
  defense_evasion: "Defense Evasion",
  credential_access: "Credential Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  command_and_control: "Command & Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

interface DetectionRule {
  id: string;
  orgId: string | null;
  name: string;
  description: string | null;
  severity: string;
  status: string;
  mitreTactic: string | null;
  mitreTechnique: string | null;
  mitreSubtechnique: string | null;
  eventTypes: string[];
  conditionTree: unknown;
  author: string | null;
  tags: string[];
  falsePositiveNotes: string | null;
  references: string[];
  isBuiltin: boolean;
  matchCount: number;
  lastMatchAt: string | null;
  createdAt: string;
}

interface TacticStat {
  mitre_tactic: string;
  rule_count: string;
  total_matches: string;
  enabled_count: string;
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function CreateRuleDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const [form, setForm] = useState({
    name: "",
    description: "",
    severity: "medium",
    mitreTactic: "",
    mitreTechnique: "",
    eventTypes: [] as string[],
    conditionJson:
      '{\n  "and": [\n    { "field": "eventType", "op": "eq", "value": "process" },\n    { "field": "processName", "op": "contains", "value": "suspicious" }\n  ]\n}',
    tags: "",
    falsePositiveNotes: "",
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      let conditionTree;
      try {
        conditionTree = JSON.parse(form.conditionJson);
      } catch {
        throw new Error("Invalid JSON in condition tree");
      }
      const res = await apiRequest("POST", "/api/detection-rules", {
        name: form.name,
        description: form.description || undefined,
        severity: form.severity,
        mitreTactic: form.mitreTactic || undefined,
        mitreTechnique: form.mitreTechnique || undefined,
        eventTypes: form.eventTypes,
        conditionTree,
        tags: form.tags ? form.tags.split(",").map((t) => t.trim()) : [],
        falsePositiveNotes: form.falsePositiveNotes || undefined,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Rule created" });
      setOpen(false);
      onSuccess();
    },
    onError: (err) => {
      toast({ title: "Failed to create rule", description: String(err), variant: "destructive" });
    },
  });

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4 mr-2" />
        Create Rule
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Custom Detection Rule</DialogTitle>
            <DialogDescription>
              Define a Sigma-compatible condition tree that evaluates against raw sensor events.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Rule Name</Label>
                <Input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Suspicious Process Execution"
                />
              </div>
              <div>
                <Label>Severity</Label>
                <Select value={form.severity} onValueChange={(v) => setForm({ ...form, severity: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="informational">Informational</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label>Description</Label>
              <Textarea
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Describe what this rule detects..."
                rows={2}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>MITRE Tactic</Label>
                <Select value={form.mitreTactic} onValueChange={(v) => setForm({ ...form, mitreTactic: v })}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select tactic" />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(TACTIC_LABELS).map(([k, v]) => (
                      <SelectItem key={k} value={k}>
                        {v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>MITRE Technique ID</Label>
                <Input
                  value={form.mitreTechnique}
                  onChange={(e) => setForm({ ...form, mitreTechnique: e.target.value })}
                  placeholder="T1059.001"
                />
              </div>
            </div>
            <div>
              <Label>Event Types (comma-separated)</Label>
              <Input
                value={form.eventTypes.join(", ")}
                onChange={(e) =>
                  setForm({
                    ...form,
                    eventTypes: e.target.value
                      .split(",")
                      .map((t) => t.trim())
                      .filter(Boolean),
                  })
                }
                placeholder="process, network, file, auth, dns, log"
              />
            </div>
            <div>
              <Label>Condition Tree (JSON)</Label>
              <Textarea
                value={form.conditionJson}
                onChange={(e) => setForm({ ...form, conditionJson: e.target.value })}
                className="font-mono text-sm"
                rows={8}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Operators: eq, neq, contains, startsWith, endsWith, regex, in, exists, gt, gte, lt, lte. Logic: and, or,
                not.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Tags (comma-separated)</Label>
                <Input
                  value={form.tags}
                  onChange={(e) => setForm({ ...form, tags: e.target.value })}
                  placeholder="custom, powershell"
                />
              </div>
              <div>
                <Label>False Positive Notes</Label>
                <Input
                  value={form.falsePositiveNotes}
                  onChange={(e) => setForm({ ...form, falsePositiveNotes: e.target.value })}
                  placeholder="May trigger on legitimate admin activity"
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMutation.mutate()} disabled={!form.name || createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create Rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default function DetectionRulesPage() {
  usePageTitle("Detection Rules");
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedRule, setSelectedRule] = useState<string | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/detection-rules", search, tacticFilter, severityFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (tacticFilter !== "all") params.set("tactic", tacticFilter);
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      const res = await apiRequest("GET", `/api/detection-rules?${params}`);
      return res.json();
    },
  });

  const { data: ruleDetail } = useQuery({
    queryKey: ["/api/detection-rules", selectedRule],
    queryFn: async () => {
      if (!selectedRule) return null;
      const res = await apiRequest("GET", `/api/detection-rules/${selectedRule}`);
      return res.json();
    },
    enabled: !!selectedRule,
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, newStatus }: { id: string; newStatus: string }) => {
      await apiRequest("PATCH", `/api/detection-rules/${id}`, { status: newStatus });
    },
    onSuccess: () => {
      toast({ title: "Rule updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/detection-rules/${id}`);
    },
    onSuccess: () => {
      toast({ title: "Rule deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] });
      setSelectedRule(null);
    },
  });

  const rules: DetectionRule[] = data?.rules || [];
  const tacticStats: TacticStat[] = data?.tacticStats || [];

  const totalRules = rules.length;
  const enabledRules = rules.filter((r) => r.status === "enabled").length;
  const totalMatches = rules.reduce((sum, r) => sum + r.matchCount, 0);
  const builtinCount = rules.filter((r) => r.isBuiltin).length;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Detection Rules</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Sigma-compatible rules that fire on raw sensor telemetry — 45 built-in MITRE ATT&CK rules included.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <CreateRuleDialog onSuccess={() => queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] })} />
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Total Rules</span>
            </div>
            <p className="text-2xl font-semibold mt-1">{isLoading ? <Skeleton className="h-8 w-12" /> : totalRules}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <ToggleRight className="h-4 w-4 text-green-500" />
              <span className="text-sm text-muted-foreground">Enabled</span>
            </div>
            <p className="text-2xl font-semibold mt-1 text-green-500">
              {isLoading ? <Skeleton className="h-8 w-12" /> : enabledRules}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-orange-500" />
              <span className="text-sm text-muted-foreground">Total Matches</span>
            </div>
            <p className="text-2xl font-semibold mt-1 text-orange-500">
              {isLoading ? <Skeleton className="h-8 w-12" /> : totalMatches}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-blue-500" />
              <span className="text-sm text-muted-foreground">Built-in</span>
            </div>
            <p className="text-2xl font-semibold mt-1">
              {isLoading ? <Skeleton className="h-8 w-12" /> : builtinCount}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* MITRE ATT&CK Tactic Grid */}
      {tacticStats.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">MITRE ATT&CK Coverage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
              {tacticStats.map((ts) => (
                <button
                  key={ts.mitre_tactic}
                  className={`rounded-md border p-2 text-left transition-colors hover:bg-muted/50 ${tacticFilter === ts.mitre_tactic ? "ring-1 ring-primary bg-muted/50" : ""}`}
                  onClick={() => setTacticFilter(tacticFilter === ts.mitre_tactic ? "all" : ts.mitre_tactic)}
                >
                  <div className="text-xs font-medium truncate">
                    {TACTIC_LABELS[ts.mitre_tactic] || ts.mitre_tactic}
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-lg font-semibold">{ts.rule_count}</span>
                    {parseInt(ts.total_matches) > 0 && (
                      <Badge variant="outline" className="text-[10px] bg-orange-500/10 text-orange-500">
                        {ts.total_matches} hits
                      </Badge>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[130px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="enabled">Enabled</SelectItem>
            <SelectItem value="disabled">Disabled</SelectItem>
            <SelectItem value="testing">Testing</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Rules List */}
      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : rules.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-3" />
            <h3 className="text-lg font-medium">No detection rules found</h3>
            <p className="text-muted-foreground text-sm mt-1">
              Rules will be seeded automatically when sensors are registered.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-1">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className={`flex items-center justify-between rounded-md border p-3 cursor-pointer transition-colors hover:bg-muted/50 ${selectedRule === rule.id ? "ring-1 ring-primary bg-muted/50" : ""}`}
              onClick={() => setSelectedRule(selectedRule === rule.id ? null : rule.id)}
            >
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className="flex flex-col items-center gap-0.5">
                  <button
                    className="p-0.5"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleMutation.mutate({
                        id: rule.id,
                        newStatus: rule.status === "enabled" ? "disabled" : "enabled",
                      });
                    }}
                  >
                    {rule.status === "enabled" ? (
                      <ToggleRight className="h-5 w-5 text-green-500" />
                    ) : (
                      <ToggleLeft className="h-5 w-5 text-zinc-400" />
                    )}
                  </button>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm truncate">{rule.name}</span>
                    {rule.isBuiltin && (
                      <Badge variant="outline" className="text-[10px] shrink-0">
                        Built-in
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                    {rule.mitreTactic && <span>{TACTIC_LABELS[rule.mitreTactic] || rule.mitreTactic}</span>}
                    {rule.mitreTechnique && <span className="font-mono">{rule.mitreTechnique}</span>}
                    {rule.eventTypes.length > 0 && (
                      <span className="text-muted-foreground">[{rule.eventTypes.join(", ")}]</span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Badge variant="outline" className={SEVERITY_COLORS[rule.severity] || ""}>
                  {rule.severity}
                </Badge>
                <div className="text-right min-w-[60px]">
                  <div className="text-sm font-medium">{rule.matchCount}</div>
                  <div className="text-[10px] text-muted-foreground">matches</div>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Rule Detail Panel */}
      {selectedRule && ruleDetail?.rule && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-lg">{ruleDetail.rule.name}</CardTitle>
              <p className="text-sm text-muted-foreground mt-0.5">{ruleDetail.rule.description}</p>
            </div>
            <div className="flex items-center gap-2">
              {!ruleDetail.rule.isBuiltin && (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    if (confirm("Delete this custom rule?")) {
                      deleteMutation.mutate(selectedRule);
                    }
                  }}
                >
                  <Trash2 className="h-3 w-3 mr-1" /> Delete
                </Button>
              )}
              <Button variant="ghost" size="icon" onClick={() => setSelectedRule(null)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="details">
              <TabsList>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="condition">Condition Tree</TabsTrigger>
                <TabsTrigger value="alerts">Recent Matches</TabsTrigger>
              </TabsList>
              <TabsContent value="details" className="mt-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <div className="text-xs text-muted-foreground">Severity</div>
                    <Badge variant="outline" className={`mt-1 ${SEVERITY_COLORS[ruleDetail.rule.severity] || ""}`}>
                      {ruleDetail.rule.severity}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Status</div>
                    <Badge variant="outline" className={`mt-1 ${STATUS_COLORS[ruleDetail.rule.status] || ""}`}>
                      {ruleDetail.rule.status}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">MITRE Tactic</div>
                    <div className="text-sm mt-1">{TACTIC_LABELS[ruleDetail.rule.mitreTactic] || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Technique</div>
                    <div className="text-sm mt-1 font-mono">{ruleDetail.rule.mitreTechnique || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Match Count</div>
                    <div className="text-xl font-semibold mt-1">{ruleDetail.rule.matchCount}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Last Match</div>
                    <div className="text-sm mt-1">{timeAgo(ruleDetail.rule.lastMatchAt)}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Author</div>
                    <div className="text-sm mt-1">{ruleDetail.rule.author || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Type</div>
                    <div className="text-sm mt-1">{ruleDetail.rule.isBuiltin ? "Built-in" : "Custom"}</div>
                  </div>
                </div>
                {ruleDetail.rule.tags?.length > 0 && (
                  <div className="mt-4">
                    <div className="text-xs text-muted-foreground mb-1">Tags</div>
                    <div className="flex flex-wrap gap-1">
                      {ruleDetail.rule.tags.map((tag: string) => (
                        <Badge key={tag} variant="secondary" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {ruleDetail.rule.falsePositiveNotes && (
                  <div className="mt-4">
                    <div className="text-xs text-muted-foreground mb-1">False Positive Notes</div>
                    <p className="text-sm">{ruleDetail.rule.falsePositiveNotes}</p>
                  </div>
                )}
                {ruleDetail.rule.references?.length > 0 && (
                  <div className="mt-4">
                    <div className="text-xs text-muted-foreground mb-1">References</div>
                    <div className="space-y-1">
                      {ruleDetail.rule.references.map((ref: string, i: number) => (
                        <a
                          key={i}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-blue-500 hover:underline block truncate"
                        >
                          {ref}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>
              <TabsContent value="condition" className="mt-4">
                <pre className="rounded-md bg-zinc-950 text-green-400 p-4 text-xs overflow-x-auto max-h-96 whitespace-pre-wrap">
                  {JSON.stringify(ruleDetail.rule.conditionTree, null, 2)}
                </pre>
              </TabsContent>
              <TabsContent value="alerts" className="mt-4">
                {(ruleDetail.recentAlerts || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground py-4 text-center">No matches recorded yet.</p>
                ) : (
                  <div className="space-y-2">
                    {(ruleDetail.recentAlerts || []).map((alert: any) => (
                      <div key={alert.id} className="flex items-center justify-between rounded-md border p-3">
                        <div>
                          <div className="font-medium text-sm">{alert.title}</div>
                          <div className="text-xs text-muted-foreground mt-0.5">
                            Sensor: {alert.sensorId?.slice(0, 8)}... | {alert.mitreTactic?.replace(/_/g, " ")}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={SEVERITY_COLORS[alert.severity] || ""}>
                            {alert.severity}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{timeAgo(alert.createdAt)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
