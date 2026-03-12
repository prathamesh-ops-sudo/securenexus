import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  ShieldCheck,
  Search,
  Plus,
  ToggleLeft,
  ToggleRight,
  Trash2,
  RefreshCw,
  Target,
  X,
  ChevronRight,
  ChevronDown,
  Code,
  Layers,
  Copy,
  Check,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

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

const TACTIC_ORDER = [
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
];

const TACTIC_DESCRIPTIONS: Record<string, string> = {
  initial_access: "Techniques used to gain initial foothold in a network",
  execution: "Techniques that run malicious code on a local or remote system",
  persistence: "Techniques used to maintain presence across restarts",
  privilege_escalation: "Techniques to gain higher-level permissions",
  defense_evasion: "Techniques to avoid detection by security tools",
  credential_access: "Techniques to steal credentials like passwords",
  discovery: "Techniques to explore the environment and gain knowledge",
  lateral_movement: "Techniques to move through the network",
  collection: "Techniques to gather data of interest",
  command_and_control: "Techniques to communicate with compromised systems",
  exfiltration: "Techniques to steal data from the network",
  impact: "Techniques to disrupt availability or compromise integrity",
};

const CONDITION_TEMPLATES: Record<string, { label: string; json: string }> = {
  simple_match: {
    label: "Simple Field Match",
    json: JSON.stringify(
      {
        and: [
          { field: "eventType", op: "eq", value: "process" },
          { field: "processName", op: "contains", value: "suspicious" },
        ],
      },
      null,
      2,
    ),
  },
  network_rule: {
    label: "Network Connection Rule",
    json: JSON.stringify(
      {
        and: [
          { field: "eventType", op: "eq", value: "network" },
          { field: "destPort", op: "in", value: [4444, 5555, 6666, 8888] },
          { field: "direction", op: "eq", value: "outbound" },
        ],
      },
      null,
      2,
    ),
  },
  file_pattern: {
    label: "File Activity Pattern",
    json: JSON.stringify(
      {
        and: [
          { field: "eventType", op: "eq", value: "file" },
          {
            or: [
              { field: "filePath", op: "regex", value: "\\.(encrypted|locked|crypt)$" },
              { field: "filePath", op: "contains", value: "ransom" },
            ],
          },
        ],
      },
      null,
      2,
    ),
  },
  auth_anomaly: {
    label: "Authentication Anomaly",
    json: JSON.stringify(
      {
        and: [
          { field: "eventType", op: "eq", value: "auth" },
          { field: "outcome", op: "eq", value: "failure" },
          { field: "failureCount", op: "gte", value: 5 },
        ],
      },
      null,
      2,
    ),
  },
  dns_exfiltration: {
    label: "DNS Exfiltration Detection",
    json: JSON.stringify(
      {
        and: [
          { field: "eventType", op: "eq", value: "dns" },
          { field: "queryLength", op: "gt", value: 50 },
          { field: "queryType", op: "in", value: ["TXT", "NULL", "CNAME"] },
        ],
      },
      null,
      2,
    ),
  },
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

function getHeatmapColor(ruleCount: number, maxCount: number): string {
  if (ruleCount === 0) return "bg-zinc-900/50 border-zinc-800";
  const intensity = Math.min(ruleCount / Math.max(maxCount, 1), 1);
  if (intensity <= 0.25) return "bg-blue-950/60 border-blue-800/40";
  if (intensity <= 0.5) return "bg-blue-900/50 border-blue-700/50";
  if (intensity <= 0.75) return "bg-blue-800/50 border-blue-600/60";
  return "bg-blue-700/50 border-blue-500/70";
}

function getMatchHeatColor(matches: number): string {
  if (matches === 0) return "text-zinc-500";
  if (matches < 10) return "text-green-400";
  if (matches < 50) return "text-yellow-400";
  if (matches < 200) return "text-orange-400";
  return "text-red-400";
}

function CreateRuleDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const defaultCondition =
    '{\n  "and": [\n    { "field": "eventType", "op": "eq", "value": "process" },\n    { "field": "processName", "op": "contains", "value": "suspicious" }\n  ]\n}';
  const [form, setForm] = useState({
    name: "",
    description: "",
    severity: "medium",
    mitreTactic: "",
    mitreTechnique: "",
    eventTypes: [] as string[],
    conditionJson: defaultCondition,
    tags: "",
    falsePositiveNotes: "",
  });

  const validateJson = (json: string): boolean => {
    try {
      const parsed = JSON.parse(json);
      if (typeof parsed !== "object" || parsed === null) {
        setJsonError("Root must be an object");
        return false;
      }
      if (!parsed.and && !parsed.or && !parsed.not && !parsed.field) {
        setJsonError('Root must contain "and", "or", "not", or "field" key');
        return false;
      }
      setJsonError(null);
      return true;
    } catch (e) {
      setJsonError(String(e instanceof Error ? e.message : e));
      return false;
    }
  };

  const handleJsonChange = (value: string) => {
    setForm({ ...form, conditionJson: value });
    if (value.trim()) {
      validateJson(value);
    } else {
      setJsonError(null);
    }
  };

  const formatJson = () => {
    try {
      const parsed = JSON.parse(form.conditionJson);
      setForm({ ...form, conditionJson: JSON.stringify(parsed, null, 2) });
      setJsonError(null);
    } catch {
      // Already showing error
    }
  };

  const copyJson = () => {
    navigator.clipboard.writeText(form.conditionJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const applyTemplate = (templateKey: string) => {
    const template = CONDITION_TEMPLATES[templateKey];
    if (template) {
      setForm({ ...form, conditionJson: template.json });
      setJsonError(null);
    }
  };

  const resetForm = () => {
    setForm({
      name: "",
      description: "",
      severity: "medium",
      mitreTactic: "",
      mitreTechnique: "",
      eventTypes: [],
      conditionJson: defaultCondition,
      tags: "",
      falsePositiveNotes: "",
    });
    setJsonError(null);
  };

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
      resetForm();
      onSuccess();
    },
    onError: (err) => {
      toast({ title: "Failed to create rule", description: String(err), variant: "destructive" });
    },
  });

  return (
    <>
      <Button onClick={() => setOpen(true)} size="sm">
        <Plus className="h-4 w-4 mr-2" />
        Create Rule
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Code className="h-5 w-5" />
              Create Custom Detection Rule
            </DialogTitle>
            <DialogDescription>
              Define a Sigma-compatible condition tree that evaluates against raw sensor events. Rules fire
              automatically on every ingested event.
            </DialogDescription>
          </DialogHeader>

          <Tabs defaultValue="builder" className="mt-2">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="builder">Rule Builder</TabsTrigger>
              <TabsTrigger value="reference">Operator Reference</TabsTrigger>
            </TabsList>

            <TabsContent value="builder" className="space-y-4 mt-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <Label>Rule Name *</Label>
                  <Input
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="e.g. Suspicious PowerShell Execution"
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label>Severity *</Label>
                  <Select value={form.severity} onValueChange={(v) => setForm({ ...form, severity: v })}>
                    <SelectTrigger className="mt-1">
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
                  placeholder="Describe what this rule detects and why it matters..."
                  rows={2}
                  className="mt-1"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>MITRE ATT&CK Tactic</Label>
                  <Select value={form.mitreTactic} onValueChange={(v) => setForm({ ...form, mitreTactic: v })}>
                    <SelectTrigger className="mt-1">
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
                    placeholder="e.g. T1059.001"
                    className="mt-1"
                  />
                </div>
              </div>

              <div>
                <Label>Event Types</Label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {["process", "network", "file", "auth", "dns", "log", "registry", "cloud"].map((et) => (
                    <button
                      key={et}
                      type="button"
                      onClick={() => {
                        const types = form.eventTypes.includes(et)
                          ? form.eventTypes.filter((t) => t !== et)
                          : [...form.eventTypes, et];
                        setForm({ ...form, eventTypes: types });
                      }}
                      className={`px-3 py-1 text-xs rounded-full border transition-colors ${
                        form.eventTypes.includes(et)
                          ? "bg-primary text-primary-foreground border-primary"
                          : "bg-muted/50 text-muted-foreground border-border hover:bg-muted"
                      }`}
                    >
                      {et}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <Label>Condition Tree (JSON) *</Label>
                  <div className="flex items-center gap-1">
                    <Select onValueChange={applyTemplate}>
                      <SelectTrigger className="h-7 text-xs w-[160px]">
                        <SelectValue placeholder="Load template..." />
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(CONDITION_TEMPLATES).map(([k, v]) => (
                          <SelectItem key={k} value={k} className="text-xs">
                            {v.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={formatJson}>
                      <Code className="h-3 w-3 mr-1" />
                      Format
                    </Button>
                    <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={copyJson}>
                      {copied ? <Check className="h-3 w-3 mr-1" /> : <Copy className="h-3 w-3 mr-1" />}
                      {copied ? "Copied" : "Copy"}
                    </Button>
                  </div>
                </div>
                <div className="relative">
                  <Textarea
                    value={form.conditionJson}
                    onChange={(e) => handleJsonChange(e.target.value)}
                    className={`font-mono text-sm leading-relaxed ${
                      jsonError ? "border-red-500 focus-visible:ring-red-500" : ""
                    }`}
                    rows={10}
                    spellCheck={false}
                  />
                  {jsonError && (
                    <div className="mt-1 text-xs text-red-500 flex items-center gap-1">
                      <X className="h-3 w-3" />
                      {jsonError}
                    </div>
                  )}
                  {!jsonError && form.conditionJson.trim() && (
                    <div className="mt-1 text-xs text-green-500 flex items-center gap-1">
                      <Check className="h-3 w-3" />
                      Valid JSON condition tree
                    </div>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Tags (comma-separated)</Label>
                  <Input
                    value={form.tags}
                    onChange={(e) => setForm({ ...form, tags: e.target.value })}
                    placeholder="custom, powershell, evasion"
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label>False Positive Notes</Label>
                  <Input
                    value={form.falsePositiveNotes}
                    onChange={(e) => setForm({ ...form, falsePositiveNotes: e.target.value })}
                    placeholder="May trigger on legitimate admin activity"
                    className="mt-1"
                  />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="reference" className="mt-4">
              <div className="rounded-md border p-4 space-y-4">
                <div>
                  <h4 className="font-medium text-sm mb-2">Comparison Operators</h4>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {[
                      ["eq", "Equal to"],
                      ["neq", "Not equal to"],
                      ["contains", "String contains"],
                      ["startsWith", "String starts with"],
                      ["endsWith", "String ends with"],
                      ["regex", "Regular expression"],
                      ["in", "Value in array"],
                      ["exists", "Field exists"],
                      ["gt / gte", "Greater than (or equal)"],
                      ["lt / lte", "Less than (or equal)"],
                    ].map(([op, desc]) => (
                      <div key={op} className="flex items-center gap-2">
                        <code className="bg-muted px-1.5 py-0.5 rounded font-mono">{op}</code>
                        <span className="text-muted-foreground">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h4 className="font-medium text-sm mb-2">Logic Operators</h4>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    {[
                      ["and", "All conditions must match"],
                      ["or", "Any condition must match"],
                      ["not", "Negates a condition"],
                    ].map(([op, desc]) => (
                      <div key={op} className="flex items-center gap-2">
                        <code className="bg-muted px-1.5 py-0.5 rounded font-mono">{op}</code>
                        <span className="text-muted-foreground">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h4 className="font-medium text-sm mb-2">Event Types</h4>
                  <div className="flex flex-wrap gap-1 text-xs">
                    {["process", "network", "file", "auth", "dns", "log", "registry", "cloud"].map((t) => (
                      <code key={t} className="bg-muted px-1.5 py-0.5 rounded font-mono">
                        {t}
                      </code>
                    ))}
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>

          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={!form.name || !!jsonError || createMutation.isPending}
            >
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
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [heatmapOpen, setHeatmapOpen] = useState(true);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/detection-rules", search, tacticFilter, severityFilter, statusFilter, typeFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (tacticFilter !== "all") params.set("tactic", tacticFilter);
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (typeFilter !== "all") params.set("type", typeFilter);
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
  const rawTacticStats: TacticStat[] = data?.tacticStats || [];

  const totalRules = rules.length;
  const enabledRules = rules.filter((r) => r.status === "enabled").length;
  const totalMatches = rules.reduce((sum, r) => sum + r.matchCount, 0);
  const builtinCount = rules.filter((r) => r.isBuiltin).length;
  const customCount = rules.filter((r) => !r.isBuiltin).length;

  const sortedTacticStats = useMemo(() => {
    const statsMap = new Map(rawTacticStats.map((ts) => [ts.mitre_tactic, ts]));
    return TACTIC_ORDER.map(
      (tactic) =>
        statsMap.get(tactic) || {
          mitre_tactic: tactic,
          rule_count: "0",
          total_matches: "0",
          enabled_count: "0",
        },
    );
  }, [rawTacticStats]);

  const maxRuleCount = useMemo(
    () => Math.max(...sortedTacticStats.map((ts) => parseInt(ts.rule_count)), 1),
    [sortedTacticStats],
  );

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
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
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
              <ShieldCheck className="h-4 w-4 text-blue-500" />
              <span className="text-sm text-muted-foreground">Built-in</span>
            </div>
            <p className="text-2xl font-semibold mt-1">
              {isLoading ? <Skeleton className="h-8 w-12" /> : builtinCount}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-purple-500" />
              <span className="text-sm text-muted-foreground">Custom</span>
            </div>
            <p className="text-2xl font-semibold mt-1 text-purple-500">
              {isLoading ? <Skeleton className="h-8 w-12" /> : customCount}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* MITRE ATT&CK Coverage Heatmap */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm font-medium">MITRE ATT&CK Coverage</CardTitle>
              <CardDescription className="text-xs ml-2">
                {sortedTacticStats.filter((ts) => parseInt(ts.rule_count) > 0).length}/12 tactics covered
              </CardDescription>
            </div>
            <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => setHeatmapOpen(!heatmapOpen)}>
              {heatmapOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </div>
        </CardHeader>
        {heatmapOpen && (
          <CardContent>
            <TooltipProvider>
              <div className="grid grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
                {sortedTacticStats.map((ts) => {
                  const ruleCount = parseInt(ts.rule_count);
                  const matchCount = parseInt(ts.total_matches);
                  const enabledCount = parseInt(ts.enabled_count);
                  const enabledPct = ruleCount > 0 ? Math.round((enabledCount / ruleCount) * 100) : 0;
                  return (
                    <Tooltip key={ts.mitre_tactic}>
                      <TooltipTrigger asChild>
                        <button
                          className={`rounded-md border p-2.5 text-left transition-all hover:scale-[1.02] ${getHeatmapColor(ruleCount, maxRuleCount)} ${
                            tacticFilter === ts.mitre_tactic ? "ring-2 ring-primary" : ""
                          }`}
                          onClick={() => setTacticFilter(tacticFilter === ts.mitre_tactic ? "all" : ts.mitre_tactic)}
                        >
                          <div className="text-xs font-medium truncate">
                            {TACTIC_LABELS[ts.mitre_tactic] || ts.mitre_tactic}
                          </div>
                          <div className="flex items-center gap-2 mt-1.5">
                            <span className="text-lg font-semibold">{ruleCount}</span>
                            <span className="text-[10px] text-muted-foreground">rules</span>
                          </div>
                          {matchCount > 0 && (
                            <div className={`text-[10px] font-medium mt-0.5 ${getMatchHeatColor(matchCount)}`}>
                              {matchCount} matches
                            </div>
                          )}
                          {ruleCount > 0 && (
                            <div className="mt-1.5">
                              <div className="h-1 rounded-full bg-zinc-800 overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-green-500/70 transition-all"
                                  style={{ width: `${enabledPct}%` }}
                                />
                              </div>
                              <div className="text-[9px] text-muted-foreground mt-0.5">{enabledPct}% enabled</div>
                            </div>
                          )}
                        </button>
                      </TooltipTrigger>
                      <TooltipContent side="bottom" className="max-w-[200px]">
                        <p className="font-medium text-xs">{TACTIC_LABELS[ts.mitre_tactic]}</p>
                        <p className="text-xs text-muted-foreground mt-1">{TACTIC_DESCRIPTIONS[ts.mitre_tactic]}</p>
                        <div className="text-xs mt-1">
                          {ruleCount} rules | {enabledCount} enabled | {matchCount} matches
                        </div>
                      </TooltipContent>
                    </Tooltip>
                  );
                })}
              </div>
            </TooltipProvider>
            <div className="flex items-center gap-4 mt-3 text-[10px] text-muted-foreground">
              <span>Density:</span>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-zinc-900/50 border border-zinc-800" />
                <span>0</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-blue-950/60 border border-blue-800/40" />
                <span>Low</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-blue-900/50 border border-blue-700/50" />
                <span>Medium</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-blue-700/50 border border-blue-500/70" />
                <span>High</span>
              </div>
            </div>
          </CardContent>
        )}
      </Card>

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
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[130px]">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="builtin">Built-in</SelectItem>
            <SelectItem value="custom">Custom</SelectItem>
          </SelectContent>
        </Select>
        {(tacticFilter !== "all" || severityFilter !== "all" || statusFilter !== "all" || typeFilter !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            className="h-9 px-2 text-xs"
            onClick={() => {
              setTacticFilter("all");
              setSeverityFilter("all");
              setStatusFilter("all");
              setTypeFilter("all");
            }}
          >
            <X className="h-3 w-3 mr-1" />
            Clear filters
          </Button>
        )}
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
                    {(ruleDetail.recentAlerts || []).map(
                      (alert: {
                        id: string;
                        title: string;
                        severity: string;
                        sensorId?: string;
                        mitreTactic?: string;
                        createdAt: string;
                      }) => (
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
                      ),
                    )}
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
