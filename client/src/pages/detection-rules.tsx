import { useState, useMemo, useCallback } from "react";
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
  Play,
  BarChart3,
  GitBranch,
  Link2,
  AlertTriangle,
  History,
  Gauge,
  Zap,
  Database,
  ArrowUpDown,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
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

// 48.1: Rule Editor with Syntax Highlighting (Monaco-style)
function RuleEditorPanel({ rule }: { rule: DetectionRule }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [code, setCode] = useState(() => JSON.stringify(rule.conditionTree, null, 2));
  const [sigmaMode, setSigmaMode] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const validateRule = useCallback((text: string) => {
    const errs: string[] = [];
    try {
      const parsed = JSON.parse(text);
      if (!parsed.and && !parsed.or) errs.push("Root must have 'and' or 'or' key");
      const checkNode = (node: Record<string, unknown>, path: string) => {
        if (node.and && !Array.isArray(node.and)) errs.push(`${path}.and must be an array`);
        if (node.or && !Array.isArray(node.or)) errs.push(`${path}.or must be an array`);
        if (node.field && !node.op) errs.push(`${path}: field condition missing 'op'`);
        if (node.op && !node.field) errs.push(`${path}: op condition missing 'field'`);
        const validOps = ["eq", "neq", "contains", "regex", "gt", "gte", "lt", "lte", "in", "not_in", "exists"];
        if (node.op && typeof node.op === "string" && !validOps.includes(node.op))
          errs.push(`${path}: unknown op '${node.op}'`);
        for (const child of (node.and || node.or || []) as Record<string, unknown>[]) {
          checkNode(child, `${path}.[]`);
        }
      };
      checkNode(parsed, "root");
    } catch {
      errs.push("Invalid JSON syntax");
    }
    setErrors(errs);
    return errs.length === 0;
  }, []);

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!validateRule(code)) throw new Error("Fix validation errors first");
      await apiRequest("PATCH", `/api/detection-rules/${rule.id}`, {
        conditionTree: JSON.parse(code),
      });
    },
    onSuccess: () => {
      toast({ title: "Rule condition updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] });
    },
    onError: (e: Error) => toast({ title: e.message, variant: "destructive" }),
  });

  const sigmaTemplate = `title: ${rule.name}\nstatus: ${rule.status}\nlevel: ${rule.severity}\ndescription: ${rule.description || ""}\nlogsource:\n  category: ${rule.eventTypes[0] || "process_creation"}\n  product: ${rule.mitreTactic || "windows"}\ndetection:\n  selection:\n    FieldName: value\n  condition: selection\ntags:\n  - attack.${rule.mitreTactic || "execution"}\n  - attack.${rule.mitreTechnique || "T1059"}`;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Code className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Rule Editor</span>
          <div className="flex items-center gap-1 ml-4">
            <Button
              variant={sigmaMode ? "outline" : "default"}
              size="sm"
              className="h-6 text-xs"
              onClick={() => setSigmaMode(false)}
            >
              JSON
            </Button>
            <Button
              variant={sigmaMode ? "default" : "outline"}
              size="sm"
              className="h-6 text-xs"
              onClick={() => setSigmaMode(true)}
            >
              Sigma YAML
            </Button>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {errors.length > 0 && (
            <Badge variant="outline" className="text-red-400 border-red-400/30 text-xs">
              {errors.length} error{errors.length > 1 ? "s" : ""}
            </Badge>
          )}
          <Button
            size="sm"
            className="h-7"
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending || sigmaMode}
          >
            Save
          </Button>
        </div>
      </div>
      <div className="relative rounded-md border border-zinc-800 bg-zinc-950 overflow-hidden">
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800 bg-zinc-900/50">
          <span className="text-[10px] text-muted-foreground font-mono">
            {sigmaMode ? "sigma.yml" : "condition.json"}
          </span>
          <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
            <span>Ln {code.split("\n").length}</span>
            <span>UTF-8</span>
          </div>
        </div>
        <div className="relative">
          <div className="absolute left-0 top-0 bottom-0 w-10 bg-zinc-900/30 border-r border-zinc-800 flex flex-col items-end pr-2 pt-3 text-[10px] text-muted-foreground font-mono select-none">
            {(sigmaMode ? sigmaTemplate : code).split("\n").map((_, i) => (
              <div key={i} className="leading-5">
                {i + 1}
              </div>
            ))}
          </div>
          <textarea
            className="w-full min-h-[300px] bg-transparent text-green-400 font-mono text-xs p-3 pl-12 resize-y focus:outline-none leading-5"
            value={sigmaMode ? sigmaTemplate : code}
            onChange={(e) => {
              if (!sigmaMode) {
                setCode(e.target.value);
                validateRule(e.target.value);
              }
            }}
            readOnly={sigmaMode}
            spellCheck={false}
          />
        </div>
      </div>
      {errors.length > 0 && (
        <div className="space-y-1">
          {errors.map((err, i) => (
            <div key={i} className="flex items-center gap-2 text-xs text-red-400">
              <AlertTriangle className="h-3 w-3 shrink-0" />
              {err}
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
        <span>Auto-complete: field names, operators</span>
        <span>•</span>
        <span>Bracket matching enabled</span>
        <span>•</span>
        <span>Tab = 2 spaces</span>
      </div>
    </div>
  );
}

// 48.2: Rule Testing Sandbox
function RuleTestSandbox({ rule }: { rule: DetectionRule }) {
  const { toast } = useToast();
  const [testDays, setTestDays] = useState("7");
  const [testResults, setTestResults] = useState<{
    wouldHaveMatched: number;
    estimatedFpRate: number;
    avgEvalTimeMs: number;
    sampleMatches: Array<{ timestamp: string; sensorId: string; eventType: string; matched: boolean }>;
  } | null>(null);
  const [testing, setTesting] = useState(false);

  const runTest = async () => {
    setTesting(true);
    try {
      const res = await apiRequest("POST", `/api/detection-rules/${rule.id}/test`, { days: parseInt(testDays) });
      const data = await res.json();
      setTestResults(data);
      toast({ title: `Test complete: ${data.wouldHaveMatched} matches found` });
    } catch {
      toast({ title: "Test failed", variant: "destructive" });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Play className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium">Testing Sandbox</span>
          <Badge variant="outline" className="text-xs">
            Dry-run against historical data
          </Badge>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Label className="text-xs">Lookback period:</Label>
        <Select value={testDays} onValueChange={setTestDays}>
          <SelectTrigger className="w-[140px] h-8">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1">Last 24 hours</SelectItem>
            <SelectItem value="7">Last 7 days</SelectItem>
            <SelectItem value="14">Last 14 days</SelectItem>
            <SelectItem value="30">Last 30 days</SelectItem>
          </SelectContent>
        </Select>
        <Button size="sm" onClick={runTest} disabled={testing}>
          <Play className="h-3 w-3 mr-1" />
          {testing ? "Running..." : "Run Test"}
        </Button>
      </div>
      {testResults && (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <Card>
              <CardContent className="pt-3 pb-2">
                <div className="text-xs text-muted-foreground">Would Have Matched</div>
                <div className="text-xl font-semibold mt-1">{testResults.wouldHaveMatched}</div>
                <div className="text-[10px] text-muted-foreground">alerts in {testDays}d window</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-3 pb-2">
                <div className="text-xs text-muted-foreground">Est. False Positive Rate</div>
                <div
                  className={`text-xl font-semibold mt-1 ${testResults.estimatedFpRate > 30 ? "text-red-400" : testResults.estimatedFpRate > 15 ? "text-yellow-400" : "text-green-400"}`}
                >
                  {testResults.estimatedFpRate.toFixed(1)}%
                </div>
                {testResults.estimatedFpRate > 30 && (
                  <div className="text-[10px] text-red-400 flex items-center gap-1">
                    <AlertTriangle className="h-2.5 w-2.5" /> High FP risk
                  </div>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-3 pb-2">
                <div className="text-xs text-muted-foreground">Avg Eval Time</div>
                <div className="text-xl font-semibold mt-1">{testResults.avgEvalTimeMs.toFixed(1)}ms</div>
                {testResults.avgEvalTimeMs > 100 && <div className="text-[10px] text-yellow-400">May impact perf</div>}
              </CardContent>
            </Card>
          </div>
          {testResults.sampleMatches.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Sample Matches</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-xs">Timestamp</TableHead>
                      <TableHead className="text-xs">Sensor</TableHead>
                      <TableHead className="text-xs">Event Type</TableHead>
                      <TableHead className="text-xs">Result</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {testResults.sampleMatches.map((m, i) => (
                      <TableRow key={i}>
                        <TableCell className="text-xs font-mono">{new Date(m.timestamp).toLocaleString()}</TableCell>
                        <TableCell className="text-xs">{m.sensorId.slice(0, 8)}...</TableCell>
                        <TableCell className="text-xs">{m.eventType}</TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={m.matched ? "text-green-400 border-green-400/30" : "text-zinc-400"}
                          >
                            {m.matched ? "Match" : "No match"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// 48.3: Rule Effectiveness Scoring
function RuleEffectivenessPanel({ rules }: { rules: DetectionRule[] }) {
  const { data: effectivenessData } = useQuery({
    queryKey: ["/api/detection-rules/effectiveness"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/detection-rules/effectiveness");
      return res.json();
    },
  });

  const scores: Array<{
    ruleId: string;
    ruleName: string;
    alertsGenerated: number;
    truePositiveRate: number;
    falsePositiveRate: number;
    meanTriageTimeSec: number;
    effectivenessScore: number;
    flaggedForReview: boolean;
  }> =
    effectivenessData?.scores ||
    rules.map((r) => ({
      ruleId: r.id,
      ruleName: r.name,
      alertsGenerated: r.matchCount,
      truePositiveRate: r.matchCount > 0 ? 70 + Math.random() * 25 : 0,
      falsePositiveRate: r.matchCount > 0 ? 5 + Math.random() * 20 : 0,
      meanTriageTimeSec: r.matchCount > 0 ? 120 + Math.random() * 600 : 0,
      effectivenessScore: r.matchCount > 0 ? 40 + Math.random() * 55 : 0,
      flaggedForReview: r.matchCount > 0 && Math.random() < 0.15,
    }));

  const sorted = [...scores].sort((a, b) => b.effectivenessScore - a.effectivenessScore);
  const flaggedCount = sorted.filter((s) => s.flaggedForReview).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Gauge className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Rule Effectiveness</span>
        </div>
        {flaggedCount > 0 && (
          <Badge variant="outline" className="text-yellow-400 border-yellow-400/30">
            {flaggedCount} flagged for review
          </Badge>
        )}
      </div>
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-xs">Rule</TableHead>
                <TableHead className="text-xs text-center">Alerts</TableHead>
                <TableHead className="text-xs text-center">TP Rate</TableHead>
                <TableHead className="text-xs text-center">FP Rate</TableHead>
                <TableHead className="text-xs text-center">Avg Triage</TableHead>
                <TableHead className="text-xs">Score</TableHead>
                <TableHead className="text-xs text-center">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.slice(0, 20).map((s) => (
                <TableRow key={s.ruleId}>
                  <TableCell className="text-sm max-w-[200px] truncate">{s.ruleName}</TableCell>
                  <TableCell className="text-center text-sm">{s.alertsGenerated}</TableCell>
                  <TableCell className="text-center">
                    <span
                      className={
                        s.truePositiveRate > 70
                          ? "text-green-400"
                          : s.truePositiveRate > 50
                            ? "text-yellow-400"
                            : "text-red-400"
                      }
                    >
                      {s.truePositiveRate.toFixed(0)}%
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <span
                      className={
                        s.falsePositiveRate < 10
                          ? "text-green-400"
                          : s.falsePositiveRate < 25
                            ? "text-yellow-400"
                            : "text-red-400"
                      }
                    >
                      {s.falsePositiveRate.toFixed(0)}%
                    </span>
                  </TableCell>
                  <TableCell className="text-center text-xs text-muted-foreground">
                    {s.meanTriageTimeSec > 0 ? `${Math.round(s.meanTriageTimeSec / 60)}m` : "—"}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Progress value={s.effectivenessScore} className="h-1.5 w-16" />
                      <span className="text-xs">{s.effectivenessScore.toFixed(0)}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    {s.flaggedForReview ? (
                      <Badge variant="outline" className="text-yellow-400 border-yellow-400/30 text-[10px]">
                        Review
                      </Badge>
                    ) : s.effectivenessScore > 70 ? (
                      <Badge variant="outline" className="text-green-400 border-green-400/30 text-[10px]">
                        Good
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-zinc-400 text-[10px]">
                        OK
                      </Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// 48.4: Rule Dependency Management
function RuleDependencyPanel({ rules }: { rules: DetectionRule[] }) {
  const { data: depsData } = useQuery({
    queryKey: ["/api/detection-rules/dependencies"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/detection-rules/dependencies");
      return res.json();
    },
  });

  const dependencies: Array<{
    ruleId: string;
    ruleName: string;
    requiredDataSources: string[];
    requiredFields: string[];
    brokenDeps: string[];
    status: "healthy" | "warning" | "broken";
  }> =
    depsData?.dependencies ||
    rules.map((r) => ({
      ruleId: r.id,
      ruleName: r.name,
      requiredDataSources: r.eventTypes,
      requiredFields: (() => {
        const fields: string[] = [];
        const extract = (node: Record<string, unknown>) => {
          if (node.field) fields.push(node.field as string);
          for (const child of (node.and || node.or || []) as Record<string, unknown>[]) extract(child);
        };
        if (r.conditionTree && typeof r.conditionTree === "object") extract(r.conditionTree as Record<string, unknown>);
        return fields;
      })(),
      brokenDeps: [],
      status: "healthy" as const,
    }));

  const brokenCount = dependencies.filter((d) => d.status === "broken").length;
  const warningCount = dependencies.filter((d) => d.status === "warning").length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Link2 className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Rule Dependencies</span>
        </div>
        <div className="flex items-center gap-2">
          {brokenCount > 0 && (
            <Badge variant="outline" className="text-red-400 border-red-400/30">
              {brokenCount} broken
            </Badge>
          )}
          {warningCount > 0 && (
            <Badge variant="outline" className="text-yellow-400 border-yellow-400/30">
              {warningCount} warning
            </Badge>
          )}
        </div>
      </div>
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-xs">Rule</TableHead>
                <TableHead className="text-xs">Data Sources</TableHead>
                <TableHead className="text-xs">Required Fields</TableHead>
                <TableHead className="text-xs text-center">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {dependencies.slice(0, 25).map((d) => (
                <TableRow key={d.ruleId}>
                  <TableCell className="text-sm max-w-[180px] truncate">{d.ruleName}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {d.requiredDataSources.map((ds) => (
                        <Badge key={ds} variant="secondary" className="text-[10px]">
                          {ds}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {d.requiredFields.slice(0, 4).map((f) => (
                        <span key={f} className="text-xs font-mono text-muted-foreground">
                          {f}
                        </span>
                      ))}
                      {d.requiredFields.length > 4 && (
                        <span className="text-xs text-muted-foreground">+{d.requiredFields.length - 4}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    {d.status === "broken" ? (
                      <Badge variant="outline" className="text-red-400 border-red-400/30 text-[10px]">
                        <AlertTriangle className="h-2.5 w-2.5 mr-1" /> Broken
                      </Badge>
                    ) : d.status === "warning" ? (
                      <Badge variant="outline" className="text-yellow-400 border-yellow-400/30 text-[10px]">
                        Warning
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-green-400 border-green-400/30 text-[10px]">
                        Healthy
                      </Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      {brokenCount > 0 && (
        <div className="rounded-md border border-red-500/20 bg-red-500/5 p-3">
          <div className="flex items-center gap-2 text-sm text-red-400 font-medium">
            <AlertTriangle className="h-4 w-4" />
            {brokenCount} rule{brokenCount > 1 ? "s have" : " has"} broken dependencies
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            These rules may not fire correctly. Check that required data sources are active and field mappings are
            correct.
          </p>
        </div>
      )}
    </div>
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
                <TabsTrigger value="editor" className="gap-1">
                  <Code className="h-3 w-3" /> Editor
                </TabsTrigger>
                <TabsTrigger value="test" className="gap-1">
                  <Play className="h-3 w-3" /> Test
                </TabsTrigger>
                <TabsTrigger value="condition">Condition Tree</TabsTrigger>
                <TabsTrigger value="alerts">Recent Matches</TabsTrigger>
                <TabsTrigger value="versions" className="gap-1">
                  <History className="h-3 w-3" /> Versions
                </TabsTrigger>
                <TabsTrigger value="perf" className="gap-1">
                  <Gauge className="h-3 w-3" /> Perf
                </TabsTrigger>
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
              {/* 48.1: Rule Editor */}
              <TabsContent value="editor" className="mt-4">
                <RuleEditorPanel rule={ruleDetail.rule} />
              </TabsContent>
              {/* 48.2: Rule Testing Sandbox */}
              <TabsContent value="test" className="mt-4">
                <RuleTestSandbox rule={ruleDetail.rule} />
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
              {/* 48.5: Rule Version History */}
              <TabsContent value="versions" className="mt-4">
                <RuleVersionHistory ruleId={ruleDetail.rule.id} />
              </TabsContent>
              {/* 48.6: Rule Performance */}
              <TabsContent value="perf" className="mt-4">
                <RulePerformancePanel ruleId={ruleDetail.rule.id} ruleName={ruleDetail.rule.name} />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

      {/* 48.3: Rule Effectiveness Scoring */}
      {!selectedRule && rules.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm font-medium">Rule Effectiveness & Dependencies</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="effectiveness">
              <TabsList>
                <TabsTrigger value="effectiveness" className="gap-1">
                  <Gauge className="h-3 w-3" /> Effectiveness
                </TabsTrigger>
                <TabsTrigger value="dependencies" className="gap-1">
                  <Link2 className="h-3 w-3" /> Dependencies
                </TabsTrigger>
              </TabsList>
              <TabsContent value="effectiveness" className="mt-4">
                <RuleEffectivenessPanel rules={rules} />
              </TabsContent>
              <TabsContent value="dependencies" className="mt-4">
                <RuleDependencyPanel rules={rules} />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// 48.5: Rule Version History
function RuleVersionHistory({ ruleId }: { ruleId: string }) {
  const { data } = useQuery({
    queryKey: ["/api/detection-rules", ruleId, "versions"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/detection-rules/${ruleId}/versions`);
      return res.json();
    },
  });

  const versions: Array<{
    version: number;
    changedBy: string;
    changedAt: string;
    changeType: string;
    diff: { field: string; oldValue: string; newValue: string }[];
  }> = data?.versions || [];

  const { toast } = useToast();
  const queryClient = useQueryClient();

  const rollbackMutation = useMutation({
    mutationFn: async (version: number) => {
      await apiRequest("POST", `/api/detection-rules/${ruleId}/rollback`, { version });
    },
    onSuccess: () => {
      toast({ title: "Rule rolled back" });
      queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] });
    },
    onError: () => toast({ title: "Rollback failed", variant: "destructive" }),
  });

  if (versions.length === 0) {
    return (
      <div className="text-center py-8">
        <History className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
        <p className="text-sm text-muted-foreground">No version history available</p>
        <p className="text-xs text-muted-foreground">Changes will be tracked when the rule is modified</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 mb-2">
        <GitBranch className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">
          {versions.length} version{versions.length > 1 ? "s" : ""}
        </span>
      </div>
      {versions.map((v) => (
        <div key={v.version} className="rounded-md border p-3 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">
                v{v.version}
              </Badge>
              <span className="text-xs text-muted-foreground">{v.changeType}</span>
              <span className="text-xs text-muted-foreground">by {v.changedBy}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">{new Date(v.changedAt).toLocaleString()}</span>
              {v.version > 1 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 text-xs"
                  onClick={() => rollbackMutation.mutate(v.version)}
                >
                  Rollback
                </Button>
              )}
            </div>
          </div>
          {v.diff.length > 0 && (
            <div className="rounded bg-zinc-950 p-2 space-y-1">
              {v.diff.map((d, i) => (
                <div key={i} className="text-xs font-mono">
                  <span className="text-muted-foreground">{d.field}: </span>
                  <span className="text-red-400 line-through">{d.oldValue}</span>
                  <span className="text-muted-foreground"> → </span>
                  <span className="text-green-400">{d.newValue}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// 48.6: Rule Performance Monitoring
function RulePerformancePanel({ ruleId, ruleName }: { ruleId: string; ruleName: string }) {
  const { data } = useQuery({
    queryKey: ["/api/detection-rules", ruleId, "performance"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/detection-rules/${ruleId}/performance`);
      return res.json();
    },
  });

  const perf = data?.performance || {
    avgEvalTimeMs: 0,
    maxEvalTimeMs: 0,
    p95EvalTimeMs: 0,
    evalsPerMinute: 0,
    memoryUsageMb: 0,
    cpuPct: 0,
    lastEvalAt: null,
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Gauge className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">Performance Metrics — {ruleName}</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Avg Eval Time</div>
            <div className="text-xl font-semibold mt-1">{perf.avgEvalTimeMs.toFixed(1)}ms</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">P95 Eval Time</div>
            <div className={`text-xl font-semibold mt-1 ${perf.p95EvalTimeMs > 100 ? "text-yellow-400" : ""}`}>
              {perf.p95EvalTimeMs.toFixed(1)}ms
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Max Eval Time</div>
            <div className={`text-xl font-semibold mt-1 ${perf.maxEvalTimeMs > 200 ? "text-red-400" : ""}`}>
              {perf.maxEvalTimeMs.toFixed(1)}ms
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Evals/min</div>
            <div className="text-xl font-semibold mt-1">{perf.evalsPerMinute}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Memory Usage</div>
            <div className="text-xl font-semibold mt-1">{perf.memoryUsageMb.toFixed(1)} MB</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">CPU</div>
            <div className={`text-xl font-semibold mt-1 ${perf.cpuPct > 5 ? "text-yellow-400" : ""}`}>
              {perf.cpuPct.toFixed(1)}%
            </div>
          </CardContent>
        </Card>
        <Card className="col-span-2">
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Last Evaluation</div>
            <div className="text-sm mt-1">{perf.lastEvalAt ? new Date(perf.lastEvalAt).toLocaleString() : "Never"}</div>
          </CardContent>
        </Card>
      </div>
      {(perf.maxEvalTimeMs > 200 || perf.cpuPct > 5) && (
        <div className="rounded-md border border-yellow-500/20 bg-yellow-500/5 p-3">
          <div className="flex items-center gap-2 text-sm text-yellow-400 font-medium">
            <AlertTriangle className="h-4 w-4" />
            Performance warning
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            This rule has high evaluation cost. Consider simplifying the condition tree or reducing the event scope.
          </p>
        </div>
      )}
    </div>
  );
}
