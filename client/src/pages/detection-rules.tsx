import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Crosshair,
  Search,
  Plus,
  RefreshCw,
  ToggleLeft,
  ToggleRight,
  Trash2,
  ChevronDown,
  ChevronRight,
  Tag,
  Lock,
  Zap,
  Filter,
  Download,
  Eye,
  AlertTriangle,
  Activity,
  BarChart3,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  severity: string;
  category: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreTechniqueId?: string;
  tags: string[];
  platforms: string[];
  eventTypes: string[];
  status: string;
  isBuiltin: boolean;
  isCommunity: boolean;
  totalMatches: number;
  lastMatchedAt?: string;
  falsePositiveRate: number;
  ruleSource: string;
  version: number;
  createdAt: string;
}

interface RuleStats {
  total: number;
  builtin: number;
  custom: number;
  active: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; icon: React.ReactNode }> = {
  critical: {
    color: "text-red-400",
    bg: "bg-red-500/10 border-red-500/20",
    icon: <ShieldAlert className="h-3 w-3" />,
  },
  high: {
    color: "text-orange-400",
    bg: "bg-orange-500/10 border-orange-500/20",
    icon: <Shield className="h-3 w-3" />,
  },
  medium: {
    color: "text-yellow-400",
    bg: "bg-yellow-500/10 border-yellow-500/20",
    icon: <Shield className="h-3 w-3" />,
  },
  low: {
    color: "text-blue-400",
    bg: "bg-blue-500/10 border-blue-500/20",
    icon: <Shield className="h-3 w-3" />,
  },
  informational: {
    color: "text-slate-400",
    bg: "bg-slate-500/10 border-slate-500/20",
    icon: <Shield className="h-3 w-3" />,
  },
};

const MITRE_TACTIC_COLORS: Record<string, string> = {
  "Initial Access": "text-rose-400",
  Execution: "text-orange-400",
  Persistence: "text-yellow-400",
  "Privilege Escalation": "text-amber-400",
  "Defense Evasion": "text-lime-400",
  "Credential Access": "text-emerald-400",
  Discovery: "text-cyan-400",
  "Lateral Movement": "text-blue-400",
  Collection: "text-violet-400",
  "Command and Control": "text-fuchsia-400",
  Exfiltration: "text-pink-400",
  Impact: "text-red-500",
};

const MITRE_TACTICS = Object.keys(MITRE_TACTIC_COLORS);

function severityBadge(severity: string) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.medium;
  return (
    <Badge variant="outline" className={`${cfg.bg} ${cfg.color} text-xs px-1.5 py-0 gap-1`}>
      {cfg.icon}
      {severity}
    </Badge>
  );
}

function formatDate(ts?: string) {
  if (!ts) return "never";
  return new Date(ts).toLocaleDateString();
}

// ─── Rule Row ─────────────────────────────────────────────────────────────────

function RuleRow({ rule, onToggle }: { rule: DetectionRule; onToggle: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const { toast } = useToast();
  const tacticColor = MITRE_TACTIC_COLORS[rule.mitreTactic ?? ""] ?? "text-slate-400";

  const deleteMutation = useMutation({
    mutationFn: () =>
      apiRequest("DELETE", `/api/native/detection-rules/${rule.id}`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/detection-rules"] });
      toast({ title: "Rule deleted" });
    },
    onError: (err: any) =>
      toast({ title: "Cannot delete rule", description: err.message, variant: "destructive" }),
  });

  return (
    <div
      className={`rounded-lg border transition-colors ${
        rule.status === "active"
          ? "border-slate-700/50 bg-slate-800/40"
          : "border-slate-700/30 bg-slate-900/40 opacity-60"
      }`}
    >
      {/* Main row */}
      <div
        className="flex items-center gap-4 p-4 cursor-pointer select-none"
        onClick={() => setExpanded((v) => !v)}
      >
        {/* Expand toggle */}
        <span className="text-slate-500 shrink-0">
          {expanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </span>

        {/* Severity */}
        <div className="shrink-0">{severityBadge(rule.severity)}</div>

        {/* Name + description */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-white truncate">{rule.name}</span>
            {rule.isBuiltin && (
              <Lock className="h-3 w-3 text-slate-500 shrink-0" title="Built-in rule" />
            )}
          </div>
          {rule.mitreTactic && (
            <span className={`text-xs ${tacticColor}`}>
              {rule.mitreTactic}
              {rule.mitreTechniqueId && (
                <span className="text-slate-500 ml-1">· {rule.mitreTechniqueId}</span>
              )}
            </span>
          )}
        </div>

        {/* Stats */}
        <div className="hidden md:flex items-center gap-6 text-xs">
          <div className="text-center">
            <p className="text-slate-500 uppercase tracking-wider">Matches</p>
            <p className={`font-medium ${rule.totalMatches > 0 ? "text-white" : "text-slate-600"}`}>
              {rule.totalMatches.toLocaleString()}
            </p>
          </div>
          <div className="text-center">
            <p className="text-slate-500 uppercase tracking-wider">Last Hit</p>
            <p className="text-slate-400">{formatDate(rule.lastMatchedAt)}</p>
          </div>
        </div>

        {/* Enable/disable toggle */}
        <div
          className="shrink-0"
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
        >
          <Switch
            checked={rule.status === "active"}
            className="data-[state=checked]:bg-emerald-600"
          />
        </div>

        {/* Delete (custom rules only) */}
        {!rule.isBuiltin && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 w-7 p-0 text-slate-500 hover:text-red-400 shrink-0"
            onClick={(e) => {
              e.stopPropagation();
              deleteMutation.mutate();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/30 pt-3 space-y-3">
          {rule.description && (
            <p className="text-sm text-slate-400">{rule.description}</p>
          )}
          <div className="flex flex-wrap gap-4 text-xs">
            {rule.mitreTechnique && (
              <div>
                <span className="text-slate-500">Technique: </span>
                <span className="text-slate-300">{rule.mitreTechnique}</span>
              </div>
            )}
            {rule.platforms.length > 0 && (
              <div>
                <span className="text-slate-500">Platforms: </span>
                <span className="text-slate-300">{rule.platforms.join(", ")}</span>
              </div>
            )}
            {rule.eventTypes.length > 0 && (
              <div>
                <span className="text-slate-500">Event types: </span>
                <span className="text-slate-300">{rule.eventTypes.join(", ")}</span>
              </div>
            )}
            <div>
              <span className="text-slate-500">Source: </span>
              <span className="text-slate-300 capitalize">{rule.ruleSource}</span>
            </div>
            <div>
              <span className="text-slate-500">Version: </span>
              <span className="text-slate-300">v{rule.version}</span>
            </div>
          </div>
          {(rule.tags ?? []).length > 0 && (
            <div className="flex items-center gap-1 flex-wrap">
              <Tag className="h-3 w-3 text-slate-500" />
              {rule.tags.map((t) => (
                <Badge key={t} variant="outline" className="text-xs px-1.5 py-0 border-slate-600 text-slate-500">
                  {t}
                </Badge>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Create Rule Dialog ────────────────────────────────────────────────────────

function CreateRuleDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [category, setCategory] = useState("other");
  const [mitreTactic, setMitreTactic] = useState("");
  const [mitreTechniqueId, setMitreTechniqueId] = useState("");
  const [alertTitle, setAlertTitle] = useState("");
  const [conditionsJson, setConditionsJson] = useState(
    JSON.stringify(
      {
        type: "field",
        field: "processName",
        operator: "contains",
        value: "suspicious.exe",
      },
      null,
      2,
    ),
  );
  const [jsonError, setJsonError] = useState<string | null>(null);
  const { toast } = useToast();

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiRequest("POST", "/api/native/detection-rules", body).then((r) => r.json()),
    onSuccess: () => {
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["/api/native/detection-rules"] });
      toast({ title: "Detection rule created" });
    },
    onError: (err: any) =>
      toast({ title: "Failed to create rule", description: err.message, variant: "destructive" }),
  });

  function handleSubmit() {
    let conditions;
    try {
      conditions = JSON.parse(conditionsJson);
      setJsonError(null);
    } catch {
      setJsonError("Invalid JSON in conditions");
      return;
    }

    createMutation.mutate({
      name,
      description,
      severity,
      category,
      mitreTactic: mitreTactic || undefined,
      mitreTechniqueId: mitreTechniqueId || undefined,
      alertTitle: alertTitle || name,
      conditions,
    });
  }

  return (
    <>
      <Button className="bg-cyan-600 hover:bg-cyan-700 text-white gap-2" onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" />
        Custom Rule
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="bg-slate-900 border-slate-700 max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-white">Create Custom Detection Rule</DialogTitle>
            <DialogDescription className="text-slate-400">
              Define a new detection rule using a condition tree (Sigma-compatible JSON format).
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2 space-y-1">
                <Label className="text-slate-300">Rule Name *</Label>
                <Input
                  placeholder="e.g. Suspicious curl Upload"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                />
              </div>

              <div className="space-y-1">
                <Label className="text-slate-300">Severity</Label>
                <Select value={severity} onValueChange={setSeverity}>
                  <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    {["critical", "high", "medium", "low", "informational"].map((s) => (
                      <SelectItem key={s} value={s} className="text-slate-200 capitalize">
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label className="text-slate-300">Category</Label>
                <Select value={category} onValueChange={setCategory}>
                  <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    {[
                      "malware",
                      "intrusion",
                      "phishing",
                      "data_exfiltration",
                      "privilege_escalation",
                      "lateral_movement",
                      "credential_access",
                      "reconnaissance",
                      "persistence",
                      "command_and_control",
                      "defense_evasion",
                      "other",
                    ].map((c) => (
                      <SelectItem key={c} value={c} className="text-slate-200 capitalize">
                        {c.replace(/_/g, " ")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label className="text-slate-300">MITRE Tactic</Label>
                <Select value={mitreTactic} onValueChange={setMitreTactic}>
                  <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                    <SelectValue placeholder="Select tactic..." />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    {MITRE_TACTICS.map((t) => (
                      <SelectItem key={t} value={t} className="text-slate-200">
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label className="text-slate-300">Technique ID</Label>
                <Input
                  placeholder="e.g. T1059.001"
                  value={mitreTechniqueId}
                  onChange={(e) => setMitreTechniqueId(e.target.value)}
                  className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                />
              </div>

              <div className="col-span-2 space-y-1">
                <Label className="text-slate-300">Alert Title Template</Label>
                <Input
                  placeholder="e.g. Suspicious Upload on {hostname} by {username}"
                  value={alertTitle}
                  onChange={(e) => setAlertTitle(e.target.value)}
                  className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                />
                <p className="text-xs text-slate-500">
                  Placeholders: {"{hostname}"}, {"{processName}"}, {"{username}"}, {"{srcIp}"}, {"{dstIp}"}
                </p>
              </div>

              <div className="col-span-2 space-y-1">
                <Label className="text-slate-300">Condition Tree (JSON)</Label>
                <Textarea
                  value={conditionsJson}
                  onChange={(e) => {
                    setConditionsJson(e.target.value);
                    setJsonError(null);
                  }}
                  rows={8}
                  className="bg-slate-800 border-slate-600 text-slate-200 font-mono text-xs placeholder:text-slate-500"
                  spellCheck={false}
                />
                {jsonError && <p className="text-xs text-red-400">{jsonError}</p>}
                <p className="text-xs text-slate-500">
                  Supported types: <code>field</code>, <code>and</code>, <code>or</code>, <code>not</code>.
                  Field operators: equals, contains, regex, gt, in, exists, etc.
                </p>
              </div>

              <div className="col-span-2 space-y-1">
                <Label className="text-slate-300">Description</Label>
                <Textarea
                  placeholder="Describe what this rule detects and why it's suspicious..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  className="bg-slate-800 border-slate-600 text-slate-200 placeholder:text-slate-500"
                />
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" className="text-slate-400 hover:text-white" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              onClick={handleSubmit}
              disabled={!name || createMutation.isPending}
            >
              {createMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Plus className="h-4 w-4 mr-2" />
              )}
              Create Rule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── MITRE Coverage Map ───────────────────────────────────────────────────────

function MitreCoverageMap({ rules }: { rules: DetectionRule[] }) {
  const byTactic = MITRE_TACTICS.map((tactic) => {
    const tacticRules = rules.filter((r) => r.mitreTactic === tactic && r.status === "active");
    return { tactic, count: tacticRules.length };
  });

  const max = Math.max(...byTactic.map((t) => t.count), 1);

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium text-white">MITRE ATT&CK Coverage</h3>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
        {byTactic.map(({ tactic, count }) => {
          const color = MITRE_TACTIC_COLORS[tactic] ?? "text-slate-400";
          const fillPct = Math.round((count / max) * 100);
          return (
            <div
              key={tactic}
              className="rounded-lg border border-slate-700/50 bg-slate-800/40 p-3 space-y-2"
            >
              <p className={`text-xs font-medium ${color} leading-tight`}>{tactic}</p>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-current rounded-full transition-all duration-500"
                    style={{ width: `${fillPct}%` }}
                  />
                </div>
                <span className="text-xs text-slate-400 shrink-0">{count}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function DetectionRulesPage() {
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterTactic, setFilterTactic] = useState<string>("all");
  const [filterType, setFilterType] = useState<string>("all");
  const [activeTab, setActiveTab] = useState("rules");
  const { toast } = useToast();

  const { data, isLoading } = useQuery<{ data: DetectionRule[]; meta: RuleStats }>({
    queryKey: ["/api/native/detection-rules"],
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiRequest("PATCH", `/api/native/detection-rules/${id}`, { status }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/detection-rules"] });
    },
    onError: () => toast({ title: "Failed to toggle rule", variant: "destructive" }),
  });

  const allRules = data?.data ?? [];
  const meta = data?.meta ?? { total: 0, builtin: 0, custom: 0, active: 0 };

  const filteredRules = allRules.filter((r) => {
    const matchSearch =
      !search ||
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      (r.mitreTactic ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (r.mitreTechniqueId ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (r.description ?? "").toLowerCase().includes(search.toLowerCase());

    const matchSeverity = filterSeverity === "all" || r.severity === filterSeverity;
    const matchTactic = filterTactic === "all" || r.mitreTactic === filterTactic;
    const matchType =
      filterType === "all" ||
      (filterType === "builtin" && r.isBuiltin) ||
      (filterType === "custom" && !r.isBuiltin) ||
      (filterType === "active" && r.status === "active") ||
      (filterType === "disabled" && r.status !== "active");

    return matchSearch && matchSeverity && matchTactic && matchType;
  });

  function handleToggle(rule: DetectionRule) {
    const newStatus = rule.status === "active" ? "disabled" : "active";
    toggleMutation.mutate({ id: rule.id, status: newStatus });
  }

  const criticalCount = filteredRules.filter((r) => r.severity === "critical").length;
  const highCount = filteredRules.filter((r) => r.severity === "high").length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Crosshair className="h-6 w-6 text-violet-400" />
            Detection Rules
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            {meta.active} active rules covering MITRE ATT&CK. No EDR license required.
          </p>
        </div>
        <CreateRuleDialog />
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          {
            icon: <ShieldCheck className="h-5 w-5 text-emerald-400" />,
            label: "Active Rules",
            value: meta.active,
            color: "bg-emerald-500/10",
          },
          {
            icon: <Lock className="h-5 w-5 text-cyan-400" />,
            label: "Built-in",
            value: meta.builtin,
            color: "bg-cyan-500/10",
          },
          {
            icon: <Zap className="h-5 w-5 text-violet-400" />,
            label: "Custom",
            value: meta.custom,
            color: "bg-violet-500/10",
          },
          {
            icon: <ShieldAlert className="h-5 w-5 text-red-400" />,
            label: "Critical Rules",
            value: allRules.filter((r) => r.severity === "critical").length,
            color: "bg-red-500/10",
          },
        ].map((s) => (
          <Card key={s.label} className="bg-slate-900/60 border-slate-700/50">
            <CardContent className="p-4 flex items-center gap-3">
              <div className={`p-2 rounded-lg ${s.color}`}>{s.icon}</div>
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wider">{s.label}</p>
                <p className="text-2xl font-bold text-white">{s.value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-slate-800 border-slate-700">
          <TabsTrigger
            value="rules"
            className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white"
          >
            Rules ({filteredRules.length})
          </TabsTrigger>
          <TabsTrigger
            value="coverage"
            className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white"
          >
            Coverage Map
          </TabsTrigger>
        </TabsList>

        {/* Rules list */}
        <TabsContent value="rules" className="mt-4 space-y-4">
          {/* Filter bar */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <Input
                placeholder="Search rules, tactics, techniques..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
              />
            </div>

            <Select value={filterSeverity} onValueChange={setFilterSeverity}>
              <SelectTrigger className="w-36 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                <SelectItem value="all" className="text-slate-200">All severities</SelectItem>
                {["critical", "high", "medium", "low", "informational"].map((s) => (
                  <SelectItem key={s} value={s} className="text-slate-200 capitalize">
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={filterTactic} onValueChange={setFilterTactic}>
              <SelectTrigger className="w-44 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue placeholder="MITRE Tactic" />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                <SelectItem value="all" className="text-slate-200">All tactics</SelectItem>
                {MITRE_TACTICS.map((t) => (
                  <SelectItem key={t} value={t} className="text-slate-200">
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-36 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                {[
                  { value: "all", label: "All rules" },
                  { value: "active", label: "Active only" },
                  { value: "disabled", label: "Disabled" },
                  { value: "builtin", label: "Built-in" },
                  { value: "custom", label: "Custom" },
                ].map((o) => (
                  <SelectItem key={o.value} value={o.value} className="text-slate-200">
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Rule list */}
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full rounded-lg" />
              ))}
            </div>
          ) : filteredRules.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <Shield className="h-10 w-10 mx-auto mb-3 opacity-40" />
              <p>No rules match your filters.</p>
              {allRules.length === 0 && (
                <p className="text-sm mt-2">
                  Click "Seed Detection Rules" on the Native Sensors page to load built-in rules.
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              {filteredRules.map((rule) => (
                <RuleRow key={rule.id} rule={rule} onToggle={() => handleToggle(rule)} />
              ))}
            </div>
          )}
        </TabsContent>

        {/* Coverage map */}
        <TabsContent value="coverage" className="mt-4">
          <Card className="bg-slate-900/60 border-slate-700/50">
            <CardContent className="p-6">
              <MitreCoverageMap rules={allRules} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
