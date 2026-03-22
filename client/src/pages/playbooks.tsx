import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { formatRelativeTime, formatDateShort } from "@/lib/i18n";
import { usePageTitle } from "@/hooks/use-page-title";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Plus,
  Trash2,
  Pencil,
  Play,
  BookOpen,
  Zap,
  CheckCircle,
  Clock,
  Loader2,
  XCircle,
  AlertTriangle,
  Activity,
  Workflow,
  ArrowUp,
  ArrowDown,
  Settings,
  Bell,
  Shield,
  ShieldCheck,
  Target,
  Tag,
  UserCheck,
  Ban,
  Mail,
  Globe,
  Server,
  FileX,
  UserX,
  Skull,
  X,
  ChevronDown,
  Eye,
  Send,
  Ticket,
  Gauge,
  Timer,
  Undo2,
  GitBranch,
  Beaker,
  Crosshair,
  RotateCcw,
  Hash,
  Fingerprint,
  Maximize2,
  Copy,
  Undo2 as UndoIcon,
  Redo2,
  Map,
  Layers,
  BarChart3,
  Diff,
  FlaskConical,
  MonitorPlay,
  RefreshCw,
  Download,
  TrendingUp,
  CircleDot,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import type {
  Playbook,
  PlaybookExecution,
  PlaybookApproval,
  PlaybookVersion,
  PlaybookSimulation,
  BlastRadiusPreview,
  PlaybookRollbackPlan,
} from "@shared/schema";

interface FlowNode {
  id: string;
  type: "trigger" | "action" | "condition" | "approval";
  data: {
    trigger?: string;
    actionType?: string;
    conditionType?: string;
    label: string;
    config?: Record<string, string>;
  };
}

interface FlowEdge {
  source: string;
  target: string;
  label?: string;
}

interface FlowGraph {
  nodes: FlowNode[];
  edges: FlowEdge[];
}

const PALETTE_TRIGGERS = [
  { value: "alert_created", label: "Alert Created", icon: Bell },
  { value: "alert_critical", label: "Alert Critical", icon: AlertTriangle },
  { value: "incident_created", label: "Incident Created", icon: Shield },
  { value: "incident_escalated", label: "Incident Escalated", icon: Zap },
  { value: "manual", label: "Manual", icon: Play },
] as const;

const PALETTE_ACTIONS = [
  { value: "auto_triage", label: "Auto Triage", icon: Target },
  { value: "assign_analyst", label: "Assign Analyst", icon: UserCheck },
  { value: "change_status", label: "Change Status", icon: Settings },
  { value: "add_tag", label: "Add Tag", icon: Tag },
  { value: "escalate", label: "Escalate", icon: Zap },
  { value: "create_jira_ticket", label: "Create Jira Ticket", icon: Ticket },
  { value: "create_servicenow_ticket", label: "ServiceNow Ticket", icon: Ticket },
  { value: "notify_slack", label: "Notify Slack", icon: Send },
  { value: "notify_teams", label: "Notify Teams", icon: Send },
  { value: "notify_email", label: "Notify Email", icon: Mail },
  { value: "notify_webhook", label: "Notify Webhook", icon: Globe },
  { value: "isolate_host", label: "Isolate Host", icon: Server },
  { value: "block_ip", label: "Block IP", icon: Ban },
  { value: "block_domain", label: "Block Domain", icon: Ban },
  { value: "quarantine_file", label: "Quarantine File", icon: FileX },
  { value: "disable_user", label: "Disable User", icon: UserX },
  { value: "kill_process", label: "Kill Process", icon: Skull },
] as const;

const PALETTE_CONDITIONS = [
  { value: "severity_check", label: "Severity Check", icon: Gauge },
  { value: "source_check", label: "Source Check", icon: Eye },
  { value: "time_check", label: "Time Check", icon: Timer },
] as const;

const PALETTE_GATES = [{ value: "approval_gate", label: "Approval Gate", icon: ShieldCheck }] as const;

const TRIGGER_OPTIONS = [
  { value: "alert_created", label: "Alert Created" },
  { value: "alert_critical", label: "Alert Critical" },
  { value: "incident_created", label: "Incident Created" },
  { value: "incident_escalated", label: "Incident Escalated" },
  { value: "manual", label: "Manual" },
] as const;

const ROLLBACK_ACTION_TYPES = [
  "isolate_host",
  "block_ip",
  "block_domain",
  "quarantine_file",
  "disable_user",
  "kill_process",
];

function hasRollbackableActions(actionsExecuted: unknown): boolean {
  if (!Array.isArray(actionsExecuted)) return false;
  return actionsExecuted.some((a: any) => {
    const actionType = a?.actionType || a?.type || "";
    return ROLLBACK_ACTION_TYPES.includes(actionType);
  });
}

function triggerLabel(trigger: string): string {
  return TRIGGER_OPTIONS.find((t) => t.value === trigger)?.label || trigger;
}

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return (
        <Badge variant="default" data-testid={`badge-status-${status}`}>
          <CheckCircle className="h-3 w-3 mr-1" />
          Active
        </Badge>
      );
    case "draft":
      return (
        <Badge variant="secondary" data-testid={`badge-status-${status}`}>
          <Pencil className="h-3 w-3 mr-1" />
          Draft
        </Badge>
      );
    case "inactive":
      return (
        <Badge variant="outline" data-testid={`badge-status-${status}`}>
          Inactive
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" data-testid={`badge-status-${status}`}>
          {status}
        </Badge>
      );
  }
}

function executionStatusBadge(status: string) {
  switch (status) {
    case "completed":
      return (
        <Badge variant="default" data-testid={`badge-exec-status-${status}`}>
          <CheckCircle className="h-3 w-3 mr-1" />
          Completed
        </Badge>
      );
    case "running":
      return (
        <Badge variant="secondary" data-testid={`badge-exec-status-${status}`}>
          <Loader2 className="h-3 w-3 mr-1 animate-spin" />
          Running
        </Badge>
      );
    case "failed":
      return (
        <Badge variant="destructive" data-testid={`badge-exec-status-${status}`}>
          <XCircle className="h-3 w-3 mr-1" />
          Failed
        </Badge>
      );
    case "awaiting_approval":
      return (
        <Badge
          variant="outline"
          className="no-default-hover-elevate no-default-active-elevate border-yellow-500/40 text-yellow-400"
          data-testid={`badge-exec-status-${status}`}
        >
          <Clock className="h-3 w-3 mr-1" />
          Awaiting Approval
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" data-testid={`badge-exec-status-${status}`}>
          {status}
        </Badge>
      );
  }
}

function getNodeIcon(node: FlowNode) {
  if (node.type === "trigger") {
    const found = PALETTE_TRIGGERS.find((t) => t.value === node.data.trigger);
    return found ? found.icon : Bell;
  }
  if (node.type === "action") {
    const found = PALETTE_ACTIONS.find((a) => a.value === node.data.actionType);
    return found ? found.icon : Settings;
  }
  if (node.type === "condition") {
    const found = PALETTE_CONDITIONS.find((c) => c.value === node.data.conditionType);
    return found ? found.icon : Eye;
  }
  if (node.type === "approval") {
    return ShieldCheck;
  }
  return Settings;
}

function getNodeBorderColor(type: string) {
  switch (type) {
    case "trigger":
      return "border-l-blue-500";
    case "action":
      return "border-l-green-500";
    case "condition":
      return "border-l-orange-500";
    case "approval":
      return "border-l-purple-500";
    default:
      return "border-l-muted-foreground";
  }
}

function getNodeTypeBadge(type: string) {
  switch (type) {
    case "trigger":
      return (
        <Badge
          variant="outline"
          className="text-[10px] no-default-hover-elevate no-default-active-elevate border-blue-500/40 text-blue-400"
        >
          Trigger
        </Badge>
      );
    case "action":
      return (
        <Badge
          variant="outline"
          className="text-[10px] no-default-hover-elevate no-default-active-elevate border-green-500/40 text-green-400"
        >
          Action
        </Badge>
      );
    case "condition":
      return (
        <Badge
          variant="outline"
          className="text-[10px] no-default-hover-elevate no-default-active-elevate border-orange-500/40 text-orange-400"
        >
          Condition
        </Badge>
      );
    case "approval":
      return (
        <Badge
          variant="outline"
          className="text-[10px] no-default-hover-elevate no-default-active-elevate border-purple-500/40 text-purple-400"
        >
          Approval
        </Badge>
      );
    default:
      return null;
  }
}

function generateEdges(nodes: FlowNode[]): FlowEdge[] {
  const edges: FlowEdge[] = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    const edge: FlowEdge = { source: nodes[i].id, target: nodes[i + 1].id };
    if (nodes[i].type === "condition") {
      edge.label = "true";
    }
    edges.push(edge);
  }
  return edges;
}

function parseFlowFromActions(actions: unknown): FlowGraph {
  if (Array.isArray(actions) && actions.length > 0) {
    const first = actions[0];
    if (first && typeof first === "object" && "nodes" in first) {
      return first as FlowGraph;
    }
  }
  return { nodes: [], edges: [] };
}

let nodeCounter = 0;
function nextNodeId() {
  nodeCounter++;
  return `node-${Date.now()}-${nodeCounter}`;
}

function NodeConfigPanel({ node, onUpdate }: { node: FlowNode; onUpdate: (config: Record<string, string>) => void }) {
  const config = node.data.config || {};

  const updateField = (key: string, value: string) => {
    onUpdate({ ...config, [key]: value });
  };

  if (node.type === "trigger") {
    return (
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Trigger Configuration</h4>
        <p className="text-xs text-muted-foreground">Trigger: {node.data.label}</p>
      </div>
    );
  }

  if (node.type === "approval") {
    return (
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Approval Gate Configuration
        </h4>
        <div className="space-y-1.5">
          <Label className="text-xs">Approver Role</Label>
          <Input
            placeholder="e.g. soc_lead, admin"
            value={config.approverRole || ""}
            onChange={(e) => updateField("approverRole", e.target.value)}
            data-testid="config-approver-role"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Approval Message</Label>
          <Textarea
            placeholder="Describe what needs to be approved..."
            value={config.message || ""}
            onChange={(e) => updateField("message", e.target.value)}
            className="resize-none text-xs"
            rows={3}
            data-testid="config-approval-message"
          />
        </div>
      </div>
    );
  }

  if (node.type === "condition") {
    const condType = node.data.conditionType;
    return (
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Condition Configuration
        </h4>
        {condType === "severity_check" && (
          <div className="space-y-1.5">
            <Label className="text-xs">Severity</Label>
            <Select value={config.severity || ""} onValueChange={(v) => updateField("severity", v)}>
              <SelectTrigger data-testid="config-severity">
                <SelectValue placeholder="Select severity..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}
        {condType === "source_check" && (
          <div className="space-y-1.5">
            <Label className="text-xs">Source</Label>
            <Input
              placeholder="e.g. CrowdStrike EDR"
              value={config.source || ""}
              onChange={(e) => updateField("source", e.target.value)}
              data-testid="config-source"
            />
          </div>
        )}
        {condType === "time_check" && (
          <>
            <div className="space-y-1.5">
              <Label className="text-xs">Start Hour (0-23)</Label>
              <Input
                type="number"
                placeholder="0"
                value={config.startHour || ""}
                onChange={(e) => updateField("startHour", e.target.value)}
                data-testid="config-start-hour"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">End Hour (0-23)</Label>
              <Input
                type="number"
                placeholder="23"
                value={config.endHour || ""}
                onChange={(e) => updateField("endHour", e.target.value)}
                data-testid="config-end-hour"
              />
            </div>
          </>
        )}
      </div>
    );
  }

  const actionType = node.data.actionType;
  return (
    <div className="space-y-3">
      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Action Configuration</h4>
      {(actionType === "notify_slack" || actionType === "notify_teams") && (
        <div className="space-y-1.5">
          <Label className="text-xs">Channel</Label>
          <Input
            placeholder="#channel-name"
            value={config.channel || ""}
            onChange={(e) => updateField("channel", e.target.value)}
            data-testid="config-channel"
          />
        </div>
      )}
      {actionType === "notify_email" && (
        <div className="space-y-1.5">
          <Label className="text-xs">Recipients</Label>
          <Input
            placeholder="email@example.com"
            value={config.recipients || ""}
            onChange={(e) => updateField("recipients", e.target.value)}
            data-testid="config-recipients"
          />
        </div>
      )}
      {actionType === "notify_webhook" && (
        <div className="space-y-1.5">
          <Label className="text-xs">Webhook URL</Label>
          <Input
            placeholder="https://..."
            value={config.webhookUrl || ""}
            onChange={(e) => updateField("webhookUrl", e.target.value)}
            data-testid="config-webhook-url"
          />
        </div>
      )}
      {actionType === "assign_analyst" && (
        <div className="space-y-1.5">
          <Label className="text-xs">Analyst</Label>
          <Input
            placeholder="analyst@example.com"
            value={config.analyst || ""}
            onChange={(e) => updateField("analyst", e.target.value)}
            data-testid="config-analyst"
          />
        </div>
      )}
      {actionType === "change_status" && (
        <div className="space-y-1.5">
          <Label className="text-xs">New Status</Label>
          <Input
            placeholder="investigating"
            value={config.status || ""}
            onChange={(e) => updateField("status", e.target.value)}
            data-testid="config-status"
          />
        </div>
      )}
      {actionType === "add_tag" && (
        <div className="space-y-1.5">
          <Label className="text-xs">Tag</Label>
          <Input
            placeholder="tag-name"
            value={config.tag || ""}
            onChange={(e) => updateField("tag", e.target.value)}
            data-testid="config-tag"
          />
        </div>
      )}
      {(actionType === "block_ip" || actionType === "block_domain") && (
        <div className="space-y-1.5">
          <Label className="text-xs">Duration (hours)</Label>
          <Input
            type="number"
            placeholder="24"
            value={config.duration || ""}
            onChange={(e) => updateField("duration", e.target.value)}
            data-testid="config-duration"
          />
        </div>
      )}
      {(actionType === "create_jira_ticket" || actionType === "create_servicenow_ticket") && (
        <>
          <div className="space-y-1.5">
            <Label className="text-xs">Project / Queue</Label>
            <Input
              placeholder="SEC"
              value={config.project || ""}
              onChange={(e) => updateField("project", e.target.value)}
              data-testid="config-project"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Priority</Label>
            <Input
              placeholder="high"
              value={config.priority || ""}
              onChange={(e) => updateField("priority", e.target.value)}
              data-testid="config-priority"
            />
          </div>
        </>
      )}
      {![
        "notify_slack",
        "notify_teams",
        "notify_email",
        "notify_webhook",
        "assign_analyst",
        "change_status",
        "add_tag",
        "block_ip",
        "block_domain",
        "create_jira_ticket",
        "create_servicenow_ticket",
      ].includes(actionType || "") && (
        <div className="space-y-1.5">
          <Label className="text-xs">Parameters</Label>
          <Input
            placeholder="Additional config..."
            value={config.params || ""}
            onChange={(e) => updateField("params", e.target.value)}
            data-testid="config-params"
          />
        </div>
      )}
    </div>
  );
}

function configSummary(node: FlowNode): string {
  const cfg = node.data.config;
  if (!cfg) return "";
  if (node.type === "approval") {
    const parts: string[] = [];
    if (cfg.approverRole) parts.push(`role: ${cfg.approverRole}`);
    if (cfg.message) parts.push(`msg: ${cfg.message.substring(0, 40)}${cfg.message.length > 40 ? "..." : ""}`);
    return parts.join(", ");
  }
  const parts = Object.entries(cfg)
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}: ${v}`);
  return parts.join(", ");
}

// ─── 20.1 Workflow Editor Enhancements ────────────────────────────────────
// Undo/redo history, copy/paste, zoom-to-fit, minimap, step grouping, routing
function useUndoRedo<T>(initial: T) {
  const [history, setHistory] = useState<T[]>([initial]);
  const [pointer, setPointer] = useState(0);
  const current = history[pointer];
  const canUndo = pointer > 0;
  const canRedo = pointer < history.length - 1;
  const push = useCallback(
    (val: T) => {
      setHistory((prev) => [...prev.slice(0, pointer + 1), val]);
      setPointer((prev) => prev + 1);
    },
    [pointer],
  );
  const undo = useCallback(() => {
    if (canUndo) setPointer((p) => p - 1);
  }, [canUndo]);
  const redo = useCallback(() => {
    if (canRedo) setPointer((p) => p + 1);
  }, [canRedo]);
  return { current, push, undo, redo, canUndo, canRedo };
}

function VisualBuilder({
  nodes,
  setNodes,
  selectedNodeId,
  setSelectedNodeId,
}: {
  nodes: FlowNode[];
  setNodes: (nodes: FlowNode[]) => void;
  selectedNodeId: string | null;
  setSelectedNodeId: (id: string | null) => void;
}) {
  const addNode = useCallback(
    (type: "trigger" | "action" | "condition" | "approval", value: string, label: string) => {
      const newNode: FlowNode = {
        id: nextNodeId(),
        type,
        data: {
          label,
          config: {},
          ...(type === "trigger" ? { trigger: value } : {}),
          ...(type === "action" ? { actionType: value } : {}),
          ...(type === "condition" ? { conditionType: value } : {}),
        },
      };
      setNodes([...nodes, newNode]);
      setSelectedNodeId(newNode.id);
    },
    [nodes, setNodes, setSelectedNodeId],
  );

  const removeNode = useCallback(
    (id: string) => {
      setNodes(nodes.filter((n) => n.id !== id));
      if (selectedNodeId === id) setSelectedNodeId(null);
    },
    [nodes, setNodes, selectedNodeId, setSelectedNodeId],
  );

  const moveNode = useCallback(
    (idx: number, dir: -1 | 1) => {
      const newIdx = idx + dir;
      if (newIdx < 0 || newIdx >= nodes.length) return;
      const updated = [...nodes];
      [updated[idx], updated[newIdx]] = [updated[newIdx], updated[idx]];
      setNodes(updated);
    },
    [nodes, setNodes],
  );

  const updateNodeConfig = useCallback(
    (id: string, config: Record<string, string>) => {
      setNodes(nodes.map((n) => (n.id === id ? { ...n, data: { ...n.data, config } } : n)));
    },
    [nodes, setNodes],
  );

  const selectedNode = nodes.find((n) => n.id === selectedNodeId);

  return (
    <div className="flex gap-4 flex-1 min-h-0">
      <div className="w-52 flex-shrink-0 overflow-y-auto space-y-4" data-testid="panel-palette">
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Triggers</h4>
          <div className="space-y-1">
            {PALETTE_TRIGGERS.map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.value}
                  className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded-md text-xs hover-elevate"
                  onClick={() => addNode("trigger", t.value, t.label)}
                  data-testid={`palette-trigger-${t.value}`}
                >
                  <Icon className="h-3.5 w-3.5 text-blue-400 flex-shrink-0" />
                  <span className="truncate">{t.label}</span>
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Actions</h4>
          <div className="space-y-1">
            {PALETTE_ACTIONS.map((a) => {
              const Icon = a.icon;
              return (
                <button
                  key={a.value}
                  className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded-md text-xs hover-elevate"
                  onClick={() => addNode("action", a.value, a.label)}
                  data-testid={`palette-action-${a.value}`}
                >
                  <Icon className="h-3.5 w-3.5 text-green-400 flex-shrink-0" />
                  <span className="truncate">{a.label}</span>
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Conditions</h4>
          <div className="space-y-1">
            {PALETTE_CONDITIONS.map((c) => {
              const Icon = c.icon;
              return (
                <button
                  key={c.value}
                  className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded-md text-xs hover-elevate"
                  onClick={() => addNode("condition", c.value, c.label)}
                  data-testid={`palette-condition-${c.value}`}
                >
                  <Icon className="h-3.5 w-3.5 text-orange-400 flex-shrink-0" />
                  <span className="truncate">{c.label}</span>
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Gates</h4>
          <div className="space-y-1">
            {PALETTE_GATES.map((g) => {
              const Icon = g.icon;
              return (
                <button
                  key={g.value}
                  className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded-md text-xs hover-elevate"
                  onClick={() => addNode("approval", g.value, g.label)}
                  data-testid={`palette-gate-${g.value}`}
                >
                  <Icon className="h-3.5 w-3.5 text-purple-400 flex-shrink-0" />
                  <span className="truncate">{g.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col gap-4 min-h-0">
        <div className="flex-1 overflow-y-auto" data-testid="panel-canvas">
          {nodes.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Workflow className="h-10 w-10 mb-3" />
              <p className="text-sm">No nodes in flow</p>
              <p className="text-xs mt-1">Click items from the palette to build your workflow</p>
            </div>
          ) : (
            <div className="space-y-0">
              {nodes.map((node, idx) => {
                const Icon = getNodeIcon(node);
                const isSelected = selectedNodeId === node.id;
                const summary = configSummary(node);
                return (
                  <div key={node.id}>
                    <div
                      className={`flex items-center gap-2 p-3 rounded-md border-l-4 cursor-pointer transition-colors ${getNodeBorderColor(node.type)} ${isSelected ? "bg-muted/60 ring-1 ring-primary/30" : "bg-muted/20"}`}
                      onClick={() => setSelectedNodeId(isSelected ? null : node.id)}
                      data-testid={`canvas-node-${node.id}`}
                    >
                      <Icon className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium truncate">{node.data.label}</span>
                          {getNodeTypeBadge(node.type)}
                        </div>
                        {summary && <p className="text-xs text-muted-foreground mt-0.5 truncate">{summary}</p>}
                      </div>
                      <div className="flex items-center gap-0.5 flex-shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            moveNode(idx, -1);
                          }}
                          disabled={idx === 0}
                          data-testid={`button-move-up-${node.id}`}
                        >
                          <ArrowUp className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            moveNode(idx, 1);
                          }}
                          disabled={idx === nodes.length - 1}
                          data-testid={`button-move-down-${node.id}`}
                        >
                          <ArrowDown className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            removeNode(node.id);
                          }}
                          data-testid={`button-remove-node-${node.id}`}
                        >
                          <X className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                    {idx < nodes.length - 1 && (
                      <div className="flex items-center justify-center py-1">
                        <div className="flex flex-col items-center">
                          <div className="w-px h-3 bg-muted-foreground/30" />
                          <ChevronDown className="h-3 w-3 text-muted-foreground/50" />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {selectedNode && (
          <Card className="flex-shrink-0" data-testid="panel-config">
            <CardContent className="p-4">
              <NodeConfigPanel node={selectedNode} onUpdate={(config) => updateNodeConfig(selectedNode.id, config)} />
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

export default function PlaybooksPage() {
  const { toast } = useToast();
  const [showDialog, setShowDialog] = useState(false);
  const [editingPlaybook, setEditingPlaybook] = useState<Playbook | null>(null);
  const [formName, setFormName] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formTrigger, setFormTrigger] = useState("");
  const [formStatus, setFormStatus] = useState("draft");
  const [flowNodes, setFlowNodes] = useState<FlowNode[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [executeDryRun, setExecuteDryRun] = useState(false);
  const [executeDialogId, setExecuteDialogId] = useState<string | null>(null);
  const [blastRadiusConfirmed, setBlastRadiusConfirmed] = useState(false);
  const [proposalObjective, setProposalObjective] = useState("");
  const [proposalSeverity, setProposalSeverity] = useState("high");
  const [proposal, setProposal] = useState<any | null>(null);
  const [selectedGovernancePlaybook, setSelectedGovernancePlaybook] = useState<string | null>(null);
  const [showSimulationDialog, setShowSimulationDialog] = useState(false);
  const [simParams, setSimParams] = useState("");
  const [showBlastRadiusDialog, setShowBlastRadiusDialog] = useState(false);
  const [blastRadiusContext, setBlastRadiusContext] = useState("");
  const [showVersionDialog, setShowVersionDialog] = useState(false);
  const [versionChangelog, setVersionChangelog] = useState("");
  const [showRollbackPlanDialog, setShowRollbackPlanDialog] = useState(false);
  const [rollbackPlanDesc, setRollbackPlanDesc] = useState("");
  const [rollbackSteps, setRollbackSteps] = useState("");
  const [diffVersion1, setDiffVersion1] = useState("");
  const [diffVersion2, setDiffVersion2] = useState("");
  const [showSimRunDialog, setShowSimRunDialog] = useState(false);
  const [simRunPlaybookId, setSimRunPlaybookId] = useState<string | null>(null);
  const [simScenarioName, setSimScenarioName] = useState("");
  const [simRunParams, setSimRunParams] = useState("");

  usePageTitle("Playbooks");
  const {
    data: playbooks,
    isLoading: playbooksLoading,
    isError: playbooksError,
    refetch: refetchPlaybooks,
  } = useQuery<Playbook[]>({
    queryKey: ["/api/playbooks"],
  });

  const {
    data: executions,
    isLoading: executionsLoading,
    isError: _executionsError,
    refetch: _refetchExecutions,
  } = useQuery<(PlaybookExecution & { playbookName?: string })[]>({
    queryKey: ["/api/playbook-executions"],
  });

  const {
    data: approvals,
    isLoading: approvalsLoading,
    isError: _approvalsError,
    refetch: _refetchApprovals,
  } = useQuery<PlaybookApproval[]>({
    queryKey: ["/api/playbook-approvals"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/playbooks", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      closeDialog();
      toast({ title: "Playbook created", description: "New automation playbook has been saved." });
    },
    onError: (err: any) => {
      toast({ title: "Failed to create playbook", description: err.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiRequest("PATCH", `/api/playbooks/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      closeDialog();
      toast({ title: "Playbook updated", description: "Changes have been saved." });
    },
    onError: (err: any) => {
      toast({ title: "Failed to update playbook", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/playbooks/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-executions"] });
      toast({ title: "Playbook deleted" });
    },
    onError: (err: any) => {
      toast({ title: "Failed to delete playbook", description: err.message, variant: "destructive" });
    },
  });

  const executeBlastRadiusQuery = useQuery<BlastRadiusPreview>({
    queryKey: ["/api/playbooks", executeDialogId, "blast-radius-live"],
    queryFn: async () => {
      const res = await apiRequest("POST", `/api/playbooks/${executeDialogId}/blast-radius`, {
        executionContext: { source: "manual_execute" },
      });
      return res.json();
    },
    enabled: !!executeDialogId,
    staleTime: 0,
  });

  const executeMutation = useMutation({
    mutationFn: async ({ id, dryRun }: { id: string; dryRun: boolean }) => {
      const res = await apiRequest("POST", `/api/playbooks/${id}/execute`, { dryRun });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-executions"] });
      setExecuteDialogId(null);
      setExecuteDryRun(false);
      setBlastRadiusConfirmed(false);
      toast({ title: "Playbook executed", description: "Manual execution started." });
    },
    onError: (err: any) => {
      toast({ title: "Execution failed", description: err.message, variant: "destructive" });
    },
  });

  const decideMutation = useMutation({
    mutationFn: async ({ id, decision, note }: { id: string; decision: string; note?: string }) => {
      const res = await apiRequest("POST", `/api/playbook-approvals/${id}/decide`, { decision, note });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-approvals"] });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-executions"] });
      toast({ title: "Approval decision recorded" });
    },
    onError: (err: any) => {
      toast({ title: "Decision failed", description: err.message, variant: "destructive" });
    },
  });

  const rollbackMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/playbook-executions/${id}/rollback`, {});
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-executions"] });
      toast({
        title: "Rollback initiated",
        description: `Created ${Array.isArray(data) ? data.length : 0} rollback record(s)`,
      });
    },
    onError: (err: any) => {
      toast({ title: "Rollback failed", description: err.message, variant: "destructive" });
    },
  });

  const { data: playbookVersions, isLoading: versionsLoading } = useQuery<PlaybookVersion[]>({
    queryKey: ["/api/playbook-versions", selectedGovernancePlaybook],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/playbooks/${selectedGovernancePlaybook}/versions`);
      return res.json();
    },
    enabled: !!selectedGovernancePlaybook,
  });

  const { data: simulations, isLoading: simulationsLoading } = useQuery<PlaybookSimulation[]>({
    queryKey: ["/api/playbooks", selectedGovernancePlaybook, "simulations"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/playbooks/${selectedGovernancePlaybook}/simulations`);
      return res.json();
    },
    enabled: !!selectedGovernancePlaybook,
  });

  const { data: blastPreviews, isLoading: blastLoading } = useQuery<BlastRadiusPreview[]>({
    queryKey: ["/api/playbooks", selectedGovernancePlaybook, "blast-radius"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/playbooks/${selectedGovernancePlaybook}/blast-radius`);
      return res.json();
    },
    enabled: !!selectedGovernancePlaybook,
  });

  const { data: rollbackPlans, isLoading: rollbackPlansLoading } = useQuery<PlaybookRollbackPlan[]>({
    queryKey: ["/api/playbooks", selectedGovernancePlaybook, "rollback-plans"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/playbooks/${selectedGovernancePlaybook}/rollback-plans`);
      return res.json();
    },
    enabled: !!selectedGovernancePlaybook,
  });

  // ─── 20.2 Execution Monitoring Dashboard ────────────────────────────────
  const {
    data: execDashboard,
    isLoading: execDashLoading,
    refetch: refetchExecDash,
  } = useQuery<any>({
    queryKey: ["/api/playbook-executions/dashboard"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-executions/dashboard");
      return r.json();
    },
  });

  // ─── 20.3 Version Diffing ────────────────────────────────────────────────
  const {
    data: versionDiff,
    isFetching: diffLoading,
    refetch: fetchDiff,
  } = useQuery<any>({
    queryKey: ["/api/playbook-versions", diffVersion1, "diff", diffVersion2],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbook-versions/${diffVersion1}/diff/${diffVersion2}`);
      return r.json();
    },
    enabled: false,
  });

  // ─── 20.4 Enhanced Simulation ────────────────────────────────────────────
  const simulatePlaybookMutation = useMutation({
    mutationFn: async ({
      playbookId,
      scenarioName,
      parameters,
    }: {
      playbookId: string;
      scenarioName: string;
      parameters: any;
    }) => {
      const r = await apiRequest("POST", `/api/playbooks/${playbookId}/simulate`, { scenarioName, parameters });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Simulation completed" });
      setShowSimRunDialog(false);
      setSimScenarioName("");
      setSimRunParams("");
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks", selectedGovernancePlaybook, "simulations"] });
    },
    onError: (err: any) => toast({ title: "Simulation failed", description: err.message, variant: "destructive" }),
  });

  const createVersionMutation = useMutation({
    mutationFn: async ({ playbookId, changelog }: { playbookId: string; changelog: string }) => {
      const res = await apiRequest("POST", `/api/playbooks/${playbookId}/versions`, { changeDescription: changelog });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-versions", selectedGovernancePlaybook] });
      setShowVersionDialog(false);
      setVersionChangelog("");
      toast({ title: "Version created" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const activateVersionMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/playbook-versions/${id}/activate`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-versions", selectedGovernancePlaybook] });
      toast({ title: "Version activated" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const rollbackVersionMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/playbook-versions/${id}/rollback`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-versions", selectedGovernancePlaybook] });
      toast({ title: "Rolled back to this version" });
    },
    onError: (err: any) => toast({ title: "Rollback failed", description: err.message, variant: "destructive" }),
  });

  const runSimulationMutation = useMutation({
    mutationFn: async ({ playbookId, parameters }: { playbookId: string; parameters?: Record<string, unknown> }) => {
      const res = await apiRequest("POST", `/api/playbooks/${playbookId}/simulate`, { parameters });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks", selectedGovernancePlaybook, "simulations"] });
      setShowSimulationDialog(false);
      setSimParams("");
      toast({ title: "Simulation complete" });
    },
    onError: (err: any) => toast({ title: "Simulation failed", description: err.message, variant: "destructive" }),
  });

  const createBlastRadiusMutation = useMutation({
    mutationFn: async ({
      playbookId,
      triggerContext,
    }: {
      playbookId: string;
      triggerContext?: Record<string, unknown>;
    }) => {
      const res = await apiRequest("POST", `/api/playbooks/${playbookId}/blast-radius`, { triggerContext });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks", selectedGovernancePlaybook, "blast-radius"] });
      setShowBlastRadiusDialog(false);
      setBlastRadiusContext("");
      toast({ title: "Blast radius preview generated" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const createRollbackPlanMutation = useMutation({
    mutationFn: async ({
      playbookId,
      description,
      steps,
    }: {
      playbookId: string;
      description: string;
      steps: string[];
    }) => {
      const res = await apiRequest("POST", `/api/playbooks/${playbookId}/rollback-plans`, { description, steps });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks", selectedGovernancePlaybook, "rollback-plans"] });
      setShowRollbackPlanDialog(false);
      setRollbackPlanDesc("");
      setRollbackSteps("");
      toast({ title: "Rollback plan created" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const executeRollbackPlanMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/playbook-rollback-plans/${id}/execute`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks", selectedGovernancePlaybook, "rollback-plans"] });
      toast({ title: "Rollback plan executed" });
    },
    onError: (err: any) => toast({ title: "Execution failed", description: err.message, variant: "destructive" }),
  });

  // ─── 20.7 Execution Analytics ──────────────────────────────────────────────
  const { data: analyticsData, isLoading: analyticsLoading } = useQuery<any>({
    queryKey: ["/api/playbook-analytics"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-analytics");
      return r.json();
    },
  });

  // ─── 20.8 All Response Action Types ──────────────────────────────────────────
  const { data: actionTypesData } = useQuery<any>({
    queryKey: ["/api/playbook-action-types"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-action-types");
      return r.json();
    },
  });

  // ─── 20.9 Notification Config ───────────────────────────────────────────────
  const [selectedNotifPlaybookId, setSelectedNotifPlaybookId] = useState<string | null>(null);
  const [notifChannel, setNotifChannel] = useState("email");
  const [notifSubject, setNotifSubject] = useState("");
  const [notifBody, setNotifBody] = useState("");
  const [notifRecipients, setNotifRecipients] = useState("");

  const { data: notifConfig, refetch: refetchNotifConfig } = useQuery<any>({
    queryKey: ["/api/playbooks", selectedNotifPlaybookId, "notification-config"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbooks/${selectedNotifPlaybookId}/notification-config`);
      return r.json();
    },
    enabled: !!selectedNotifPlaybookId,
  });

  const createNotifTemplateMutation = useMutation({
    mutationFn: async (data: any) => {
      const r = await apiRequest("POST", `/api/playbooks/${selectedNotifPlaybookId}/notification-templates`, data);
      return r.json();
    },
    onSuccess: () => {
      refetchNotifConfig();
      setNotifSubject("");
      setNotifBody("");
      setNotifRecipients("");
      toast({ title: "Notification template created" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const deleteNotifTemplateMutation = useMutation({
    mutationFn: async (templateId: string) => {
      await apiRequest("DELETE", `/api/playbooks/${selectedNotifPlaybookId}/notification-templates/${templateId}`);
    },
    onSuccess: () => {
      refetchNotifConfig();
      toast({ title: "Template deleted" });
    },
  });

  // ─── 20.10 Change Management ───────────────────────────────────────────────
  const [changePlaybookId, setChangePlaybookId] = useState("");
  const [changeType, setChangeType] = useState("firewall_rule");
  const [changeSummary, setChangeSummary] = useState("");
  const [changeDesc, setChangeDesc] = useState("");

  const { data: changeTickets, refetch: refetchChangeTickets } = useQuery<any>({
    queryKey: ["/api/playbook-change-tickets"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-change-tickets");
      return r.json();
    },
  });

  const createChangeTicketMutation = useMutation({
    mutationFn: async (data: any) => {
      const r = await apiRequest("POST", "/api/playbook-change-tickets", data);
      return r.json();
    },
    onSuccess: () => {
      refetchChangeTickets();
      setChangeSummary("");
      setChangeDesc("");
      toast({ title: "Change ticket created" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const approveChangeTicketMutation = useMutation({
    mutationFn: async ({ ticketId, decision, note }: { ticketId: string; decision: string; note?: string }) => {
      const r = await apiRequest("POST", `/api/playbook-change-tickets/${ticketId}/approve`, { decision, note });
      return r.json();
    },
    onSuccess: () => {
      refetchChangeTickets();
      toast({ title: "Decision recorded" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const implementChangeTicketMutation = useMutation({
    mutationFn: async (ticketId: string) => {
      const r = await apiRequest("POST", `/api/playbook-change-tickets/${ticketId}/implement`, {});
      return r.json();
    },
    onSuccess: () => {
      refetchChangeTickets();
      toast({ title: "Change implemented" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const closeChangeTicketMutation = useMutation({
    mutationFn: async (ticketId: string) => {
      const r = await apiRequest("POST", `/api/playbook-change-tickets/${ticketId}/close`, {});
      return r.json();
    },
    onSuccess: () => {
      refetchChangeTickets();
      toast({ title: "Ticket closed" });
    },
    onError: (err: any) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const proposePlaybookMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/ai/playbook-authoring/propose", {
        objective: proposalObjective,
        severity: proposalSeverity,
      });
      return res.json();
    },
    onSuccess: (data) => {
      setProposal(data);
      toast({ title: "AI proposal generated", description: "Review and approve the suggested actions." });
    },
    onError: (err: any) => {
      toast({ title: "Proposal failed", description: err.message, variant: "destructive" });
    },
  });

  function closeDialog() {
    setShowDialog(false);
    setEditingPlaybook(null);
    setFormName("");
    setFormDescription("");
    setFormTrigger("");
    setFormStatus("draft");
    setFlowNodes([]);
    setSelectedNodeId(null);
  }

  function openCreate() {
    closeDialog();
    setShowDialog(true);
  }

  function openEdit(pb: Playbook) {
    setEditingPlaybook(pb);
    setFormName(pb.name);
    setFormDescription(pb.description || "");
    setFormTrigger(pb.trigger);
    setFormStatus(pb.status);
    const flow = parseFlowFromActions(pb.actions);
    setFlowNodes(flow.nodes);
    setSelectedNodeId(null);
    setShowDialog(true);
  }

  function handleSubmit() {
    if (!formName || !formTrigger) {
      toast({
        title: "Missing required fields",
        description: "Name and trigger are required.",
        variant: "destructive",
      });
      return;
    }
    const edges = generateEdges(flowNodes);
    const flowGraph: FlowGraph = { nodes: flowNodes, edges };
    const payload = {
      name: formName,
      description: formDescription || null,
      trigger: formTrigger,
      conditions: null,
      actions: [flowGraph],
      status: formStatus,
    };
    if (editingPlaybook) {
      updateMutation.mutate({ id: editingPlaybook.id, data: payload });
    } else {
      createMutation.mutate(payload);
    }
  }

  const activeCount = playbooks?.filter((p) => p.status === "active").length || 0;
  const totalExecutions = playbooks?.reduce((sum, p) => sum + (p.triggerCount || 0), 0) || 0;
  const pendingApprovals = approvals?.filter((a) => a.status === "pending").length || 0;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Automation Playbooks</span>
          </h1>
          <p className="text-sm text-muted-foreground">
            Create and manage automated response workflows for security events
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Button onClick={openCreate} data-testid="button-create-playbook">
          <Plus className="h-4 w-4 mr-2" />
          Create Playbook
        </Button>
      </div>

      <Card data-testid="card-ai-playbook-authoring">
        <CardHeader>
          <CardTitle className="text-base">Guardrailed AI Playbook Authoring</CardTitle>
          <CardDescription>AI proposes actions; analyst reviews and approves before execution.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            <Input
              placeholder="Objective (e.g. contain lateral movement)"
              value={proposalObjective}
              onChange={(e) => setProposalObjective(e.target.value)}
              data-testid="input-proposal-objective"
            />
            <Select value={proposalSeverity} onValueChange={setProposalSeverity}>
              <SelectTrigger data-testid="select-proposal-severity">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={() => proposePlaybookMutation.mutate()}
              disabled={!proposalObjective || proposePlaybookMutation.isPending}
              data-testid="button-generate-proposal"
            >
              {proposePlaybookMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              Generate Proposal
            </Button>
          </div>
          {proposal && (
            <div className="border rounded-md p-3 space-y-2" data-testid="panel-playbook-proposal">
              <div className="text-sm font-medium">{proposal.objective}</div>
              <div className="text-xs text-muted-foreground">
                Guardrails: {(proposal.guardrailsApplied || []).join(", ")}
              </div>
              <div className="space-y-1">
                {(proposal.proposedActions || []).map((action: any, idx: number) => (
                  <div key={idx} className="text-sm flex items-center justify-between border rounded p-2">
                    <span>{action.type}</span>
                    <span className="text-xs text-muted-foreground">{action.reason}</span>
                  </div>
                ))}
              </div>
              <div className="text-xs font-medium text-amber-500">
                Requires analyst approval before playbook execution.
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Playbooks</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {playbooksLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="text-total-playbooks">
                {playbooks?.length || 0}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {playbooksLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="text-active-playbooks">
                {activeCount}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Executions</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {playbooksLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="text-total-executions">
                {totalExecutions}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Approvals</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {approvalsLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="text-pending-approvals">
                {pendingApprovals}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="playbooks" data-testid="tabs-playbooks">
        <TabsList data-testid="tabs-list">
          <TabsTrigger value="playbooks" data-testid="tab-playbooks">
            <Workflow className="h-4 w-4 mr-1.5" />
            Playbooks
          </TabsTrigger>
          <TabsTrigger value="approvals" data-testid="tab-approvals">
            <ShieldCheck className="h-4 w-4 mr-1.5" />
            Approvals
            {pendingApprovals > 0 && (
              <Badge
                variant="secondary"
                className="ml-1.5 no-default-hover-elevate no-default-active-elevate"
                data-testid="badge-pending-count"
              >
                {pendingApprovals}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="history" data-testid="tab-history">
            <Activity className="h-4 w-4 mr-1.5" />
            History
          </TabsTrigger>
          <TabsTrigger value="governance" data-testid="tab-governance">
            <Fingerprint className="h-4 w-4 mr-1.5" />
            Governance
          </TabsTrigger>
          <TabsTrigger value="monitoring" data-testid="tab-monitoring">
            <MonitorPlay className="h-4 w-4 mr-1.5" />
            Monitoring
          </TabsTrigger>
          <TabsTrigger value="versiondiff" data-testid="tab-versiondiff">
            <Diff className="h-4 w-4 mr-1.5" />
            Version Diff
          </TabsTrigger>
          <TabsTrigger value="simulation" data-testid="tab-simulation">
            <FlaskConical className="h-4 w-4 mr-1.5" />
            Simulation
          </TabsTrigger>
          <TabsTrigger value="analytics" data-testid="tab-analytics">
            <BarChart3 className="h-4 w-4 mr-1.5" />
            Analytics
          </TabsTrigger>
          <TabsTrigger value="notifications" data-testid="tab-notifications">
            <Bell className="h-4 w-4 mr-1.5" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="changes" data-testid="tab-changes">
            <Ticket className="h-4 w-4 mr-1.5" />
            Changes
          </TabsTrigger>
        </TabsList>

        <TabsContent value="playbooks" className="mt-4">
          {playbooksLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <Card key={i}>
                  <CardContent className="p-5 space-y-3">
                    <Skeleton className="h-5 w-3/4" />
                    <Skeleton className="h-4 w-full" />
                    <div className="flex gap-2">
                      <Skeleton className="h-5 w-20" />
                      <Skeleton className="h-5 w-16" />
                    </div>
                    <Skeleton className="h-4 w-1/2" />
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : playbooksError ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12" role="alert">
                <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
                  <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <p className="text-sm font-medium">Failed to load playbooks</p>
                <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching playbook data.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchPlaybooks()}>
                  Try Again
                </Button>
              </CardContent>
            </Card>
          ) : !playbooks?.length ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <BookOpen className="h-10 w-10 mb-3" />
                <p className="text-sm">No playbooks configured yet</p>
                <p className="text-xs mt-1">Create your first automation playbook to get started</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {playbooks.map((pb) => {
                const flow = parseFlowFromActions(pb.actions);
                const nodeCount = flow.nodes.length;
                return (
                  <Card key={pb.id} className="hover-elevate" data-testid={`card-playbook-${pb.id}`}>
                    <CardContent className="p-5 space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <h3 className="font-semibold text-sm truncate" data-testid={`text-playbook-name-${pb.id}`}>
                            {pb.name}
                          </h3>
                          {pb.description && (
                            <p
                              className="text-xs text-muted-foreground mt-1 line-clamp-2"
                              data-testid={`text-playbook-desc-${pb.id}`}
                            >
                              {pb.description}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-wrap">
                        {statusBadge(pb.status)}
                        <Badge variant="outline" data-testid={`badge-trigger-${pb.id}`}>
                          <Zap className="h-3 w-3 mr-1" />
                          {triggerLabel(pb.trigger)}
                        </Badge>
                        {nodeCount > 0 && (
                          <Badge variant="outline" data-testid={`badge-nodes-${pb.id}`}>
                            <Workflow className="h-3 w-3 mr-1" />
                            {nodeCount} nodes
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1" data-testid={`text-last-triggered-${pb.id}`}>
                          <Clock className="h-3 w-3" />
                          {formatRelativeTime(pb.lastTriggeredAt)}
                        </span>
                        <span data-testid={`text-trigger-count-${pb.id}`}>{pb.triggerCount || 0} runs</span>
                      </div>
                      <div className="flex items-center gap-1 pt-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => openEdit(pb)}
                          data-testid={`button-edit-${pb.id}`}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => {
                            setExecuteDryRun(false);
                            setExecuteDialogId(pb.id);
                          }}
                          disabled={executeMutation.isPending}
                          data-testid={`button-execute-${pb.id}`}
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => {
                            if (confirm("Delete this playbook? This cannot be undone.")) {
                              deleteMutation.mutate(pb.id);
                            }
                          }}
                          data-testid={`button-delete-${pb.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="approvals" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Approval Queue</CardTitle>
              <CardDescription>Review and approve pending playbook execution gates</CardDescription>
            </CardHeader>
            <CardContent>
              {approvalsLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="flex items-center gap-4">
                      <Skeleton className="h-5 w-20" />
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-4 w-24" />
                      <Skeleton className="h-4 w-16" />
                    </div>
                  ))}
                </div>
              ) : !approvals?.length ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <ShieldCheck className="h-8 w-8 mb-2" />
                  <p className="text-sm">No approval requests</p>
                  <p className="text-xs mt-1">Approval gates in playbooks will appear here when triggered</p>
                </div>
              ) : (
                <Table data-testid="table-approvals">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Playbook</TableHead>
                      <TableHead>Message</TableHead>
                      <TableHead>Requested By</TableHead>
                      <TableHead>Requested At</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {approvals.map((approval) => {
                      const pb = playbooks?.find((p) => p.id === approval.playbookId);
                      return (
                        <TableRow key={approval.id} data-testid={`row-approval-${approval.id}`}>
                          <TableCell>
                            {approval.status === "pending" && (
                              <Badge
                                variant="outline"
                                className="no-default-hover-elevate no-default-active-elevate border-yellow-500/40 text-yellow-400"
                                data-testid={`badge-approval-status-${approval.id}`}
                              >
                                <Clock className="h-3 w-3 mr-1" />
                                Pending
                              </Badge>
                            )}
                            {approval.status === "approved" && (
                              <Badge
                                variant="default"
                                className="no-default-hover-elevate no-default-active-elevate"
                                data-testid={`badge-approval-status-${approval.id}`}
                              >
                                <CheckCircle className="h-3 w-3 mr-1" />
                                Approved
                              </Badge>
                            )}
                            {approval.status === "rejected" && (
                              <Badge
                                variant="destructive"
                                className="no-default-hover-elevate no-default-active-elevate"
                                data-testid={`badge-approval-status-${approval.id}`}
                              >
                                <XCircle className="h-3 w-3 mr-1" />
                                Rejected
                              </Badge>
                            )}
                            {approval.status === "expired" && (
                              <Badge
                                variant="outline"
                                className="no-default-hover-elevate no-default-active-elevate"
                                data-testid={`badge-approval-status-${approval.id}`}
                              >
                                Expired
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <span className="font-medium text-sm" data-testid={`text-approval-playbook-${approval.id}`}>
                              {pb?.name || "Unknown"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className="text-sm text-muted-foreground"
                              data-testid={`text-approval-message-${approval.id}`}
                            >
                              {approval.approvalMessage || "\u2014"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className="text-sm text-muted-foreground"
                              data-testid={`text-approval-requested-by-${approval.id}`}
                            >
                              {approval.requestedBy || "System"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className="text-sm text-muted-foreground"
                              data-testid={`text-approval-requested-at-${approval.id}`}
                            >
                              {formatRelativeTime(approval.requestedAt)}
                            </span>
                          </TableCell>
                          <TableCell>
                            {approval.status === "pending" ? (
                              <div className="flex items-center gap-1">
                                <Button
                                  size="sm"
                                  variant="default"
                                  onClick={() => decideMutation.mutate({ id: approval.id, decision: "approved" })}
                                  disabled={decideMutation.isPending}
                                  data-testid={`button-approve-${approval.id}`}
                                >
                                  <CheckCircle className="h-3.5 w-3.5 mr-1" />
                                  Approve
                                </Button>
                                <Button
                                  size="sm"
                                  variant="destructive"
                                  onClick={() => decideMutation.mutate({ id: approval.id, decision: "rejected" })}
                                  disabled={decideMutation.isPending}
                                  data-testid={`button-reject-${approval.id}`}
                                >
                                  <XCircle className="h-3.5 w-3.5 mr-1" />
                                  Reject
                                </Button>
                              </div>
                            ) : (
                              <span
                                className="text-xs text-muted-foreground"
                                data-testid={`text-approval-decided-${approval.id}`}
                              >
                                {approval.decidedBy ? `by ${approval.decidedBy}` : "\u2014"}
                              </span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Execution History</CardTitle>
              <CardDescription>Recent playbook execution results</CardDescription>
            </CardHeader>
            <CardContent>
              {executionsLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="flex items-center gap-4">
                      <Skeleton className="h-5 w-20" />
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-4 w-24" />
                      <Skeleton className="h-4 w-16" />
                    </div>
                  ))}
                </div>
              ) : !executions?.length ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Activity className="h-8 w-8 mb-2" />
                  <p className="text-sm">No executions yet</p>
                </div>
              ) : (
                <Table data-testid="table-executions">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Playbook</TableHead>
                      <TableHead>Triggered By</TableHead>
                      <TableHead>Resource</TableHead>
                      <TableHead>Execution Time</TableHead>
                      <TableHead>When</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {executions.map((exec) => {
                      const pb = playbooks?.find((p) => p.id === exec.playbookId);
                      const canRollback = hasRollbackableActions(exec.actionsExecuted);
                      return (
                        <TableRow key={exec.id} data-testid={`row-execution-${exec.id}`}>
                          <TableCell>
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {executionStatusBadge(exec.status)}
                              {exec.dryRun && (
                                <Badge
                                  variant="outline"
                                  className="no-default-hover-elevate no-default-active-elevate border-cyan-500/40 text-cyan-400 text-[10px]"
                                  data-testid={`badge-dry-run-${exec.id}`}
                                >
                                  DRY RUN
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <span className="font-medium text-sm" data-testid={`text-exec-playbook-${exec.id}`}>
                              {exec.playbookName || pb?.name || "Unknown"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className="text-sm text-muted-foreground"
                              data-testid={`text-exec-triggered-by-${exec.id}`}
                            >
                              {exec.triggeredBy || "System"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className="text-sm text-muted-foreground"
                              data-testid={`text-exec-resource-${exec.id}`}
                            >
                              {exec.resourceType && exec.resourceId
                                ? `${exec.resourceType}:${exec.resourceId.substring(0, 8)}`
                                : "N/A"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="text-sm font-mono" data-testid={`text-exec-time-${exec.id}`}>
                              {exec.executionTimeMs ? `${exec.executionTimeMs}ms` : "\u2014"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="text-sm text-muted-foreground" data-testid={`text-exec-when-${exec.id}`}>
                              {formatRelativeTime(exec.createdAt)}
                            </span>
                          </TableCell>
                          <TableCell>
                            {canRollback && !exec.dryRun && (
                              <Button
                                size="icon"
                                variant="ghost"
                                onClick={() => {
                                  if (
                                    confirm("Rollback this execution? This will attempt to reverse all EDR actions.")
                                  ) {
                                    rollbackMutation.mutate(exec.id);
                                  }
                                }}
                                disabled={rollbackMutation.isPending}
                                data-testid={`button-rollback-${exec.id}`}
                              >
                                <Undo2 className="h-4 w-4" />
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="governance" className="mt-4 space-y-6">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div>
              <h2 className="text-lg font-semibold" data-testid="text-governance-header">
                Playbook Governance
              </h2>
              <p className="text-xs text-muted-foreground">
                Version control, simulation, blast radius analysis, and rollback plans
              </p>
            </div>
            <Select value={selectedGovernancePlaybook || ""} onValueChange={setSelectedGovernancePlaybook}>
              <SelectTrigger className="w-[260px]" data-testid="select-governance-playbook">
                <SelectValue placeholder="Select a playbook..." />
              </SelectTrigger>
              <SelectContent>
                {playbooks?.map((pb) => (
                  <SelectItem key={pb.id} value={pb.id}>
                    {pb.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {!selectedGovernancePlaybook ? (
            <Card>
              <CardContent className="p-8 text-center">
                <Fingerprint className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">
                  Select a playbook above to manage its governance settings
                </p>
              </CardContent>
            </Card>
          ) : (
            <Tabs defaultValue="versions" data-testid="tabs-governance-sub">
              <TabsList>
                <TabsTrigger value="versions">
                  <GitBranch className="h-3.5 w-3.5 mr-1" />
                  Versions
                </TabsTrigger>
                <TabsTrigger value="simulations">
                  <Beaker className="h-3.5 w-3.5 mr-1" />
                  Simulations
                </TabsTrigger>
                <TabsTrigger value="blast-radius">
                  <Crosshair className="h-3.5 w-3.5 mr-1" />
                  Blast Radius
                </TabsTrigger>
                <TabsTrigger value="rollback-plans">
                  <RotateCcw className="h-3.5 w-3.5 mr-1" />
                  Rollback Plans
                </TabsTrigger>
              </TabsList>

              <TabsContent value="versions" className="mt-4 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold">Version History</h3>
                  <Button size="sm" onClick={() => setShowVersionDialog(true)} data-testid="button-create-version">
                    <Plus className="h-3.5 w-3.5 mr-1" />
                    Create Version
                  </Button>
                </div>
                {versionsLoading ? (
                  <div className="space-y-2">
                    <Skeleton className="h-16 w-full" />
                    <Skeleton className="h-16 w-full" />
                  </div>
                ) : playbookVersions && playbookVersions.length > 0 ? (
                  <div className="space-y-2">
                    {playbookVersions.map((v) => (
                      <Card key={v.id} data-testid={`version-card-${v.id}`}>
                        <CardContent className="p-3 flex items-center justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge
                                variant="outline"
                                className="text-[9px] font-mono no-default-hover-elevate no-default-active-elevate"
                              >
                                v{v.version}
                              </Badge>
                              {v.status === "active" && (
                                <Badge className="text-[9px] bg-green-500/15 text-green-500 border-green-500/30 no-default-hover-elevate no-default-active-elevate">
                                  Active
                                </Badge>
                              )}
                              {v.changeDescription && (
                                <span className="text-xs text-muted-foreground truncate">{v.changeDescription}</span>
                              )}
                            </div>
                            <div className="text-[10px] text-muted-foreground mt-1">
                              {v.createdByName && <span>{v.createdByName} &middot; </span>}
                              {formatRelativeTime(v.createdAt)}
                            </div>
                          </div>
                          <div className="flex items-center gap-1">
                            {v.status !== "active" && (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => activateVersionMutation.mutate(v.id)}
                                disabled={activateVersionMutation.isPending}
                                data-testid={`button-activate-${v.id}`}
                              >
                                <CheckCircle className="h-3 w-3 mr-1" />
                                Activate
                              </Button>
                            )}
                            {v.status !== "active" && (
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => rollbackVersionMutation.mutate(v.id)}
                                disabled={rollbackVersionMutation.isPending}
                                data-testid={`button-rollback-version-${v.id}`}
                              >
                                <Undo2 className="h-3 w-3 mr-1" />
                                Rollback
                              </Button>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Card>
                    <CardContent className="p-8 text-center">
                      <GitBranch className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No versions yet</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Create a version snapshot to track playbook changes
                      </p>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="simulations" className="mt-4 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold">Simulation (Dry Run)</h3>
                  <Button size="sm" onClick={() => setShowSimulationDialog(true)} data-testid="button-run-simulation">
                    <Beaker className="h-3.5 w-3.5 mr-1" />
                    Run Simulation
                  </Button>
                </div>
                {simulationsLoading ? (
                  <div className="space-y-2">
                    <Skeleton className="h-20 w-full" />
                    <Skeleton className="h-20 w-full" />
                  </div>
                ) : simulations && simulations.length > 0 ? (
                  <div className="space-y-2">
                    {simulations.map((sim) => (
                      <Card key={sim.id} data-testid={`simulation-card-${sim.id}`}>
                        <CardContent className="p-3 space-y-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge
                              variant={
                                sim.status === "completed"
                                  ? "default"
                                  : sim.status === "failed"
                                    ? "destructive"
                                    : "outline"
                              }
                              className={`text-[9px] no-default-hover-elevate no-default-active-elevate ${sim.status === "completed" ? "bg-green-500/15 text-green-500 border-green-500/30" : ""}`}
                            >
                              {sim.status}
                            </Badge>
                            {sim.durationMs && (
                              <span className="text-xs font-mono text-muted-foreground">{sim.durationMs}ms</span>
                            )}
                            <span className="text-xs text-muted-foreground">{formatRelativeTime(sim.createdAt)}</span>
                          </div>
                          {sim.impactAnalysis !== null && typeof sim.impactAnalysis === "object" ? (
                            <div className="text-xs text-muted-foreground bg-muted/50 rounded p-2 font-mono whitespace-pre-wrap">
                              {String(JSON.stringify(sim.impactAnalysis, null, 2)).slice(0, 500)}
                            </div>
                          ) : null}
                          {sim.simulatedByName && (
                            <div className="text-[10px] text-muted-foreground">Simulated by {sim.simulatedByName}</div>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Card>
                    <CardContent className="p-8 text-center">
                      <Beaker className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No simulations run yet</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Run a simulation to preview playbook execution without making real changes
                      </p>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="blast-radius" className="mt-4 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold">Blast Radius Previews</h3>
                  <Button
                    size="sm"
                    onClick={() => setShowBlastRadiusDialog(true)}
                    data-testid="button-create-blast-radius"
                  >
                    <Crosshair className="h-3.5 w-3.5 mr-1" />
                    Generate Preview
                  </Button>
                </div>
                {blastLoading ? (
                  <div className="space-y-2">
                    <Skeleton className="h-24 w-full" />
                  </div>
                ) : blastPreviews && blastPreviews.length > 0 ? (
                  <div className="space-y-3">
                    {blastPreviews.map((bp) => (
                      <Card key={bp.id} data-testid={`blast-radius-card-${bp.id}`}>
                        <CardContent className="p-4 space-y-3">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge
                              variant="outline"
                              className={`text-[9px] no-default-hover-elevate no-default-active-elevate ${
                                bp.riskLevel === "critical"
                                  ? "border-red-500/30 text-red-500"
                                  : bp.riskLevel === "high"
                                    ? "border-orange-500/30 text-orange-500"
                                    : bp.riskLevel === "medium"
                                      ? "border-yellow-500/30 text-yellow-500"
                                      : "border-green-500/30 text-green-500"
                              }`}
                            >
                              Risk: {bp.riskLevel}
                            </Badge>
                            <span className="text-xs text-muted-foreground">{formatRelativeTime(bp.createdAt)}</span>
                          </div>
                          {bp.affectedEntityCount > 0 && bp.affectedEntities !== null ? (
                            <div>
                              <div className="text-xs font-medium mb-1">
                                Affected Entities ({bp.affectedEntityCount})
                              </div>
                              <div className="flex flex-wrap gap-1">
                                {Array.isArray(bp.affectedEntities) ? (
                                  (bp.affectedEntities as unknown[]).map((entity, idx) => (
                                    <Badge
                                      key={idx}
                                      variant="outline"
                                      className="text-[9px] no-default-hover-elevate no-default-active-elevate"
                                    >
                                      {typeof entity === "string" ? entity : String(JSON.stringify(entity))}
                                    </Badge>
                                  ))
                                ) : (
                                  <span className="text-xs text-muted-foreground">
                                    {String(JSON.stringify(bp.affectedEntities))}
                                  </span>
                                )}
                              </div>
                            </div>
                          ) : null}
                          {bp.riskFactors !== null && bp.riskFactors !== undefined ? (
                            <div className="text-xs text-muted-foreground">
                              <span className="font-medium">Risk Factors: </span>
                              {String(JSON.stringify(bp.riskFactors))}
                            </div>
                          ) : null}
                          {bp.rollbackPlan !== null && bp.rollbackPlan !== undefined ? (
                            <div>
                              <div className="text-xs font-medium mb-1">Rollback Plan</div>
                              <div className="text-xs text-muted-foreground">
                                {String(JSON.stringify(bp.rollbackPlan))}
                              </div>
                            </div>
                          ) : null}
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Card>
                    <CardContent className="p-8 text-center">
                      <Crosshair className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No blast radius previews yet</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Generate a preview to see what resources would be affected by this playbook
                      </p>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="rollback-plans" className="mt-4 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold">Rollback Plans</h3>
                  <Button
                    size="sm"
                    onClick={() => setShowRollbackPlanDialog(true)}
                    data-testid="button-create-rollback-plan"
                  >
                    <Plus className="h-3.5 w-3.5 mr-1" />
                    Create Plan
                  </Button>
                </div>
                {rollbackPlansLoading ? (
                  <div className="space-y-2">
                    <Skeleton className="h-20 w-full" />
                  </div>
                ) : rollbackPlans && rollbackPlans.length > 0 ? (
                  <div className="space-y-2">
                    {rollbackPlans.map((rp) => (
                      <Card key={rp.id} data-testid={`rollback-plan-card-${rp.id}`}>
                        <CardContent className="p-3 space-y-2">
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge
                                variant={
                                  rp.status === "executed"
                                    ? "default"
                                    : rp.status === "failed"
                                      ? "destructive"
                                      : "outline"
                                }
                                className={`text-[9px] no-default-hover-elevate no-default-active-elevate ${rp.status === "executed" ? "bg-green-500/15 text-green-500 border-green-500/30" : ""}`}
                              >
                                {rp.status}
                              </Badge>
                              {rp.autoRollbackEnabled && (
                                <Badge
                                  variant="outline"
                                  className="text-[9px] no-default-hover-elevate no-default-active-elevate"
                                >
                                  Auto
                                </Badge>
                              )}
                            </div>
                            {rp.status === "ready" && (
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => {
                                  if (
                                    confirm(
                                      "Execute this rollback plan? This will attempt to reverse the playbook actions.",
                                    )
                                  ) {
                                    executeRollbackPlanMutation.mutate(rp.id);
                                  }
                                }}
                                disabled={executeRollbackPlanMutation.isPending}
                                data-testid={`button-execute-rollback-${rp.id}`}
                              >
                                <RotateCcw className="h-3 w-3 mr-1" />
                                Execute
                              </Button>
                            )}
                          </div>
                          {Array.isArray(rp.rollbackSteps) && (rp.rollbackSteps as unknown[]).length > 0 ? (
                            <ol className="text-xs text-muted-foreground list-decimal list-inside space-y-0.5">
                              {(rp.rollbackSteps as unknown[]).map((step, idx) => (
                                <li key={idx}>{typeof step === "string" ? step : String(JSON.stringify(step))}</li>
                              ))}
                            </ol>
                          ) : null}
                          <div className="text-[10px] text-muted-foreground">
                            {rp.executedByName && <span>{rp.executedByName} &middot; </span>}
                            {formatRelativeTime(rp.createdAt)}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Card>
                    <CardContent className="p-8 text-center">
                      <RotateCcw className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No rollback plans yet</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Create a rollback plan to ensure safe reversal of playbook actions
                      </p>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* ─── 20.2 Execution Monitoring Dashboard ─────────────────────────── */}
              <TabsContent value="monitoring" className="mt-4">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                      <MonitorPlay className="h-5 w-5 text-blue-400" />
                      Execution Monitoring Dashboard
                    </h2>
                    <Button size="sm" variant="outline" onClick={() => refetchExecDash()}>
                      <RefreshCw className="h-3 w-3 mr-1" />
                      Refresh
                    </Button>
                  </div>

                  {execDashLoading ? (
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      {[1, 2, 3, 4].map((i) => (
                        <Skeleton key={i} className="h-24" />
                      ))}
                    </div>
                  ) : execDashboard?.summary ? (
                    <>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                        <Card>
                          <CardContent className="p-4">
                            <div className="text-xs text-muted-foreground">Total</div>
                            <div className="text-2xl font-bold">{execDashboard.summary.total}</div>
                          </CardContent>
                        </Card>
                        <Card className="border-blue-500/20">
                          <CardContent className="p-4">
                            <div className="text-xs text-muted-foreground flex items-center gap-1">
                              <Loader2 className="h-3 w-3 animate-spin" />
                              Running
                            </div>
                            <div className="text-2xl font-bold text-blue-400">{execDashboard.summary.running}</div>
                          </CardContent>
                        </Card>
                        <Card className="border-yellow-500/20">
                          <CardContent className="p-4">
                            <div className="text-xs text-muted-foreground flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Awaiting
                            </div>
                            <div className="text-2xl font-bold text-yellow-400">
                              {execDashboard.summary.awaitingApproval}
                            </div>
                          </CardContent>
                        </Card>
                        <Card className="border-green-500/20">
                          <CardContent className="p-4">
                            <div className="text-xs text-muted-foreground">Success Rate</div>
                            <div className="text-2xl font-bold text-green-400">
                              {execDashboard.summary.successRate}%
                            </div>
                          </CardContent>
                        </Card>
                        <Card className="border-red-500/20">
                          <CardContent className="p-4">
                            <div className="text-xs text-muted-foreground">Failed</div>
                            <div className="text-2xl font-bold text-red-400">{execDashboard.summary.failed}</div>
                          </CardContent>
                        </Card>
                      </div>

                      {/* Active Executions */}
                      {execDashboard.activeExecutions?.length > 0 && (
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <CircleDot className="h-4 w-4 text-blue-400 animate-pulse" />
                              Active Executions ({execDashboard.activeExecutions.length})
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {execDashboard.activeExecutions.map((exec: any) => (
                                <div
                                  key={exec.id}
                                  className="flex items-center gap-3 p-2 bg-muted/10 rounded border border-border"
                                >
                                  {executionStatusBadge(exec.status)}
                                  <span className="text-sm font-medium">{exec.playbookName}</span>
                                  <span className="text-xs text-muted-foreground">{exec.triggeredBy}</span>
                                  {exec.dryRun && (
                                    <Badge variant="outline" className="text-[10px]">
                                      Dry Run
                                    </Badge>
                                  )}
                                  <span className="text-xs text-muted-foreground ml-auto">
                                    {exec.actionsExecuted} actions
                                  </span>
                                  {exec.executionTimeMs && (
                                    <span className="text-xs text-muted-foreground">
                                      {(exec.executionTimeMs / 1000).toFixed(1)}s
                                    </span>
                                  )}
                                </div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                      )}

                      {/* Per-playbook Stats */}
                      {execDashboard.perPlaybook?.length > 0 && (
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <BarChart3 className="h-4 w-4 text-purple-400" />
                              Per-Playbook Statistics
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead className="text-xs">Playbook</TableHead>
                                  <TableHead className="text-xs text-center">Total</TableHead>
                                  <TableHead className="text-xs text-center">Completed</TableHead>
                                  <TableHead className="text-xs text-center">Failed</TableHead>
                                  <TableHead className="text-xs text-center">Running</TableHead>
                                  <TableHead className="text-xs text-right">Avg Time</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {execDashboard.perPlaybook.map((stat: any) => (
                                  <TableRow key={stat.playbookId}>
                                    <TableCell className="text-sm font-medium">{stat.playbookName}</TableCell>
                                    <TableCell className="text-center text-sm">{stat.totalExecutions}</TableCell>
                                    <TableCell className="text-center text-sm text-green-400">
                                      {stat.completed}
                                    </TableCell>
                                    <TableCell className="text-center text-sm text-red-400">{stat.failed}</TableCell>
                                    <TableCell className="text-center text-sm text-blue-400">{stat.running}</TableCell>
                                    <TableCell className="text-right text-sm text-muted-foreground">
                                      {stat.avgTimeMs > 0 ? `${(stat.avgTimeMs / 1000).toFixed(1)}s` : "\u2014"}
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </CardContent>
                        </Card>
                      )}

                      {/* Recent Executions */}
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Recent Executions</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-64">
                            <div className="space-y-1">
                              {(execDashboard.recentExecutions || []).map((exec: any) => (
                                <div key={exec.id} className="flex items-center gap-2 p-2 bg-muted/10 rounded text-xs">
                                  {executionStatusBadge(exec.status)}
                                  <span className="font-medium">{exec.playbookName}</span>
                                  <span className="text-muted-foreground">{exec.triggeredBy}</span>
                                  <span className="text-muted-foreground">{exec.triggerEvent}</span>
                                  {exec.dryRun && (
                                    <Badge variant="outline" className="text-[9px]">
                                      Dry Run
                                    </Badge>
                                  )}
                                  <span className="text-muted-foreground ml-auto">{exec.actionsCount} actions</span>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        </CardContent>
                      </Card>

                      {/* Failed Executions */}
                      {execDashboard.failedExecutions?.length > 0 && (
                        <Card className="border-red-500/20">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <XCircle className="h-4 w-4 text-red-400" />
                              Failed Executions
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {execDashboard.failedExecutions.map((exec: any) => (
                                <div
                                  key={exec.id}
                                  className="p-2 bg-red-500/5 rounded border border-red-500/20 text-xs"
                                >
                                  <div className="font-medium">{exec.playbookName}</div>
                                  <div className="text-muted-foreground">
                                    {exec.triggeredBy} &mdash; {exec.error}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                      )}
                    </>
                  ) : (
                    <Card>
                      <CardContent className="py-12 text-center text-muted-foreground">
                        <MonitorPlay className="h-10 w-10 mx-auto mb-3" />
                        <p className="text-sm">No execution data available</p>
                        <p className="text-xs mt-1">Execute a playbook to see monitoring data</p>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>

              {/* ─── 20.3 Version Diffing ──────────────────────────────────────── */}
              <TabsContent value="versiondiff" className="mt-4">
                <div className="space-y-4">
                  <h2 className="text-lg font-semibold flex items-center gap-2">
                    <Diff className="h-5 w-5 text-orange-400" />
                    Playbook Version Diffing
                  </h2>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Compare Two Versions</CardTitle>
                      <CardDescription className="text-xs">
                        Select a playbook and two versions to compare changes
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <Label className="text-xs">Playbook</Label>
                        <Select
                          value={selectedGovernancePlaybook || ""}
                          onValueChange={(v) => {
                            setSelectedGovernancePlaybook(v);
                            setDiffVersion1("");
                            setDiffVersion2("");
                          }}
                        >
                          <SelectTrigger className="h-8 text-xs">
                            <SelectValue placeholder="Select playbook..." />
                          </SelectTrigger>
                          <SelectContent>
                            {(playbooks || []).map((pb) => (
                              <SelectItem key={pb.id} value={pb.id} className="text-xs">
                                {pb.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      {selectedGovernancePlaybook && playbookVersions && playbookVersions.length >= 2 && (
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <Label className="text-xs">Version A (older)</Label>
                            <Select value={diffVersion1} onValueChange={setDiffVersion1}>
                              <SelectTrigger className="h-8 text-xs">
                                <SelectValue placeholder="Select version..." />
                              </SelectTrigger>
                              <SelectContent>
                                {playbookVersions.map((v) => (
                                  <SelectItem key={v.id} value={String(v.id)} className="text-xs">
                                    v{v.version} &mdash; {v.changeDescription || "No description"}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label className="text-xs">Version B (newer)</Label>
                            <Select value={diffVersion2} onValueChange={setDiffVersion2}>
                              <SelectTrigger className="h-8 text-xs">
                                <SelectValue placeholder="Select version..." />
                              </SelectTrigger>
                              <SelectContent>
                                {playbookVersions.map((v) => (
                                  <SelectItem key={v.id} value={String(v.id)} className="text-xs">
                                    v{v.version} &mdash; {v.changeDescription || "No description"}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                      )}

                      {diffVersion1 && diffVersion2 && diffVersion1 !== diffVersion2 && (
                        <Button size="sm" onClick={() => fetchDiff()} disabled={diffLoading}>
                          {diffLoading ? (
                            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                          ) : (
                            <Diff className="h-3 w-3 mr-1" />
                          )}
                          Compare Versions
                        </Button>
                      )}

                      {selectedGovernancePlaybook && (!playbookVersions || playbookVersions.length < 2) && (
                        <p className="text-xs text-muted-foreground py-2">
                          This playbook needs at least 2 versions to compare. Create versions in the Governance tab.
                        </p>
                      )}
                    </CardContent>
                  </Card>

                  {versionDiff && (
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">
                          Diff: v{versionDiff.version1?.version} &rarr; v{versionDiff.version2?.version}
                        </CardTitle>
                        <CardDescription className="text-xs">
                          {versionDiff.summary?.totalChanges} changes: {versionDiff.summary?.added} added,{" "}
                          {versionDiff.summary?.removed} removed, {versionDiff.summary?.modified} modified
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {versionDiff.changes?.length === 0 ? (
                          <p className="text-xs text-muted-foreground py-4 text-center">No differences found</p>
                        ) : (
                          <div className="space-y-2">
                            {(versionDiff.changes || []).map((change: any, i: number) => (
                              <div
                                key={i}
                                className={`p-3 rounded border text-xs ${
                                  change.type === "added"
                                    ? "bg-green-500/5 border-green-500/20"
                                    : change.type === "removed"
                                      ? "bg-red-500/5 border-red-500/20"
                                      : "bg-yellow-500/5 border-yellow-500/20"
                                }`}
                              >
                                <div className="flex items-center gap-2 mb-1">
                                  <Badge
                                    variant="outline"
                                    className={`text-[10px] ${
                                      change.type === "added"
                                        ? "border-green-500/40 text-green-400"
                                        : change.type === "removed"
                                          ? "border-red-500/40 text-red-400"
                                          : "border-yellow-500/40 text-yellow-400"
                                    }`}
                                  >
                                    {change.type}
                                  </Badge>
                                  <span className="font-medium">{change.field}</span>
                                  {change.nodeId && (
                                    <span className="text-muted-foreground">Node: {change.nodeId}</span>
                                  )}
                                </div>
                                {change.type === "modified" && change.field !== "steps" && (
                                  <div className="grid grid-cols-2 gap-2 mt-1">
                                    <div className="p-2 bg-red-500/5 rounded">
                                      <span className="text-[10px] text-muted-foreground">Before:</span>
                                      <pre className="text-[10px] font-mono whitespace-pre-wrap">
                                        {JSON.stringify(change.oldValue, null, 2)}
                                      </pre>
                                    </div>
                                    <div className="p-2 bg-green-500/5 rounded">
                                      <span className="text-[10px] text-muted-foreground">After:</span>
                                      <pre className="text-[10px] font-mono whitespace-pre-wrap">
                                        {JSON.stringify(change.newValue, null, 2)}
                                      </pre>
                                    </div>
                                  </div>
                                )}
                                {change.type === "added" && (
                                  <pre className="text-[10px] font-mono text-green-400 mt-1 whitespace-pre-wrap">
                                    + {JSON.stringify(change.newValue, null, 2)}
                                  </pre>
                                )}
                                {change.type === "removed" && (
                                  <pre className="text-[10px] font-mono text-red-400 mt-1 whitespace-pre-wrap">
                                    - {JSON.stringify(change.oldValue, null, 2)}
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>

              {/* ─── 20.4 Simulation / Dry-Run Mode ────────────────────────────── */}
              <TabsContent value="simulation" className="mt-4">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                      <FlaskConical className="h-5 w-5 text-purple-400" />
                      Playbook Simulation Mode
                    </h2>
                  </div>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Run Simulation</CardTitle>
                      <CardDescription className="text-xs">
                        Simulate playbook execution without triggering any real actions. Actions are logged but never
                        executed.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <Label className="text-xs">Playbook</Label>
                        <Select value={simRunPlaybookId || ""} onValueChange={setSimRunPlaybookId}>
                          <SelectTrigger className="h-8 text-xs">
                            <SelectValue placeholder="Select playbook to simulate..." />
                          </SelectTrigger>
                          <SelectContent>
                            {(playbooks || []).map((pb) => (
                              <SelectItem key={pb.id} value={pb.id} className="text-xs">
                                {pb.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label className="text-xs">Scenario Name (optional)</Label>
                        <Input
                          placeholder="e.g. Ransomware containment test"
                          value={simScenarioName}
                          onChange={(e) => setSimScenarioName(e.target.value)}
                          className="h-8 text-xs"
                        />
                      </div>
                      <Button
                        size="sm"
                        onClick={() => {
                          if (simRunPlaybookId) {
                            simulatePlaybookMutation.mutate({
                              playbookId: simRunPlaybookId,
                              scenarioName: simScenarioName || "Manual simulation",
                              parameters: {},
                            });
                          }
                        }}
                        disabled={!simRunPlaybookId || simulatePlaybookMutation.isPending}
                      >
                        {simulatePlaybookMutation.isPending ? (
                          <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                        ) : (
                          <FlaskConical className="h-3 w-3 mr-1" />
                        )}
                        Run Simulation
                      </Button>
                    </CardContent>
                  </Card>

                  {simulatePlaybookMutation.data && (
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          Simulation Result: {(simulatePlaybookMutation.data as any).playbookName}
                        </CardTitle>
                        <CardDescription className="text-xs">
                          {(simulatePlaybookMutation.data as any).summary?.totalSteps} steps | Estimated:{" "}
                          {((simulatePlaybookMutation.data as any).summary?.estimatedDurationMs / 1000).toFixed(1)}s |{" "}
                          High-risk: {(simulatePlaybookMutation.data as any).summary?.highRiskSteps} | Approval gates:{" "}
                          {(simulatePlaybookMutation.data as any).summary?.approvalGates} | Destructive:{" "}
                          {(simulatePlaybookMutation.data as any).summary?.destructiveActions}
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-80">
                          <div className="space-y-2">
                            {((simulatePlaybookMutation.data as any).steps || []).map((step: any) => (
                              <div
                                key={step.step}
                                className={`p-3 rounded border text-xs ${
                                  step.riskLevel === "high"
                                    ? "bg-red-500/5 border-red-500/20"
                                    : step.riskLevel === "medium"
                                      ? "bg-yellow-500/5 border-yellow-500/20"
                                      : "bg-muted/10 border-border"
                                }`}
                              >
                                <div className="flex items-center gap-2 mb-1">
                                  <Badge variant="outline" className="text-[10px]">
                                    Step {step.step}
                                  </Badge>
                                  <Badge
                                    variant="outline"
                                    className={`text-[10px] ${
                                      step.nodeType === "action"
                                        ? "border-green-500/40 text-green-400"
                                        : step.nodeType === "condition"
                                          ? "border-orange-500/40 text-orange-400"
                                          : step.nodeType === "approval"
                                            ? "border-purple-500/40 text-purple-400"
                                            : "border-blue-500/40 text-blue-400"
                                    }`}
                                  >
                                    {step.nodeType || step.actionType}
                                  </Badge>
                                  <span className="font-medium">{step.label}</span>
                                  {step.wouldBlock && (
                                    <Badge
                                      variant="outline"
                                      className="text-[10px] border-purple-500/40 text-purple-400"
                                    >
                                      Would Block
                                    </Badge>
                                  )}
                                  {step.riskLevel && (
                                    <Badge
                                      variant={
                                        step.riskLevel === "high"
                                          ? "destructive"
                                          : step.riskLevel === "medium"
                                            ? "secondary"
                                            : "outline"
                                      }
                                      className="text-[10px]"
                                    >
                                      {step.riskLevel} risk
                                    </Badge>
                                  )}
                                  <span className="text-muted-foreground ml-auto">
                                    ~{(step.estimatedDurationMs / 1000).toFixed(1)}s
                                  </span>
                                </div>
                                {step.impact?.length > 0 && (
                                  <div className="mt-1 space-y-0.5">
                                    {step.impact.map((imp: any, j: number) => (
                                      <div
                                        key={j}
                                        className="text-[10px] text-muted-foreground flex items-center gap-1"
                                      >
                                        <span
                                          className={
                                            imp.type === "destructive"
                                              ? "text-red-400"
                                              : imp.type === "notification"
                                                ? "text-blue-400"
                                                : "text-muted-foreground"
                                          }
                                        >
                                          [{imp.type}]
                                        </span>
                                        {imp.description}
                                        {imp.reversible !== undefined && (
                                          <span className="text-muted-foreground/60">
                                            ({imp.reversible ? "reversible" : "irreversible"})
                                          </span>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}

                  {/* Past simulations from governance tab data */}
                  {simulations && simulations.length > 0 && (
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Previous Simulations</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-48">
                          <div className="space-y-1">
                            {simulations.map((sim) => (
                              <div key={sim.id} className="flex items-center gap-2 p-2 bg-muted/10 rounded text-xs">
                                <Badge
                                  variant={sim.status === "completed" ? "default" : "secondary"}
                                  className="text-[10px]"
                                >
                                  {sim.status}
                                </Badge>
                                <span className="font-medium">
                                  {(sim.simulatedActions as any)?.[0]?.label || "Simulation"}
                                </span>
                                <span className="text-muted-foreground">
                                  {Array.isArray(sim.simulatedActions) ? (sim.simulatedActions as any[]).length : 0}{" "}
                                  steps
                                </span>
                                <span className="text-muted-foreground ml-auto">
                                  {sim.durationMs ? `${(sim.durationMs / 1000).toFixed(1)}s` : "\u2014"}
                                </span>
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          )}
        </TabsContent>

        {/* ─── 20.7 Analytics Tab ──────────────────────────────────────────── */}
        <TabsContent value="analytics" className="mt-4 space-y-4" data-testid="tab-content-analytics">
          {analyticsLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <Card key={i}>
                  <CardContent className="p-5">
                    <Skeleton className="h-8 w-16 mb-2" />
                    <Skeleton className="h-4 w-24" />
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : analyticsData ? (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                    <CheckCircle className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{analyticsData.overview?.successRate ?? 0}%</div>
                    <p className="text-xs text-muted-foreground">
                      {analyticsData.overview?.completedExecutions ?? 0} completed
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Failure Rate</CardTitle>
                    <XCircle className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{analyticsData.overview?.failureRate ?? 0}%</div>
                    <p className="text-xs text-muted-foreground">
                      {analyticsData.overview?.failedExecutions ?? 0} failed
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Avg Execution Time</CardTitle>
                    <Timer className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">
                      {analyticsData.overview?.avgExecutionTimeMs
                        ? `${(analyticsData.overview.avgExecutionTimeMs / 1000).toFixed(1)}s`
                        : "—"}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {analyticsData.overview?.totalExecutions ?? 0} total runs
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Active Playbooks</CardTitle>
                    <Workflow className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{analyticsData.overview?.activePlaybooks ?? 0}</div>
                    <p className="text-xs text-muted-foreground">
                      of {analyticsData.overview?.totalPlaybooks ?? 0} total
                    </p>
                  </CardContent>
                </Card>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Most Triggered Playbooks</CardTitle>
                    <CardDescription className="text-xs">Top playbooks by execution count</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-56">
                      <div className="space-y-2">
                        {(analyticsData.mostTriggered || []).map((pb: any) => (
                          <div
                            key={pb.playbookId}
                            className="flex items-center justify-between p-2 bg-muted/10 rounded text-xs"
                          >
                            <div className="flex-1 min-w-0">
                              <div className="font-medium truncate">{pb.playbookName}</div>
                              <div className="text-muted-foreground">{pb.totalExecutions} executions</div>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="default" className="text-[10px]">
                                {pb.successRate}% success
                              </Badge>
                              <span className="text-muted-foreground">
                                {pb.avgTimeMs ? `${(pb.avgTimeMs / 1000).toFixed(1)}s avg` : "—"}
                              </span>
                            </div>
                          </div>
                        ))}
                        {!(analyticsData.mostTriggered || []).length && (
                          <p className="text-xs text-muted-foreground text-center py-4">No execution data yet</p>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">High Failure Steps</CardTitle>
                    <CardDescription className="text-xs">Steps with the highest failure rates</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-56">
                      <div className="space-y-2">
                        {(analyticsData.highFailureSteps || []).map((step: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between p-2 bg-muted/10 rounded text-xs">
                            <div className="font-medium font-mono">{step.stepId}</div>
                            <div className="flex items-center gap-2">
                              <Badge variant="destructive" className="text-[10px]">
                                {step.failureRate}% fail
                              </Badge>
                              <span className="text-muted-foreground">
                                {step.failures}/{step.total} runs
                              </span>
                            </div>
                          </div>
                        ))}
                        {!(analyticsData.highFailureSteps || []).length && (
                          <p className="text-xs text-muted-foreground text-center py-4">No failure data</p>
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </div>

              {/* 20.8 Available Response Action Types */}
              {actionTypesData && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Available Response Action Types</CardTitle>
                    <CardDescription className="text-xs">
                      {actionTypesData.totalCount} action types across {actionTypesData.categories?.length} categories
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {(actionTypesData.categories || []).map((cat: string) => (
                        <div key={cat} className="space-y-1.5">
                          <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                            {cat}
                          </div>
                          {(actionTypesData.byCategory?.[cat] || []).map((action: any) => (
                            <div
                              key={action.actionType}
                              className="flex items-center gap-2 p-1.5 bg-muted/10 rounded text-xs"
                            >
                              <Badge
                                variant="outline"
                                className={`text-[10px] no-default-hover-elevate no-default-active-elevate ${
                                  action.risk === "high"
                                    ? "border-red-500/40 text-red-400"
                                    : action.risk === "medium"
                                      ? "border-orange-500/40 text-orange-400"
                                      : "border-green-500/40 text-green-400"
                                }`}
                              >
                                {action.risk}
                              </Badge>
                              <span className="font-medium">{action.label}</span>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Execution Time Trend */}
              {analyticsData.executionTimeTrend && analyticsData.executionTimeTrend.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Execution Time Trend</CardTitle>
                    <CardDescription className="text-xs">
                      Last {analyticsData.executionTimeTrend.length} completed executions
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-end gap-1 h-24">
                      {analyticsData.executionTimeTrend.map((t: any, idx: number) => {
                        const maxTime = Math.max(
                          ...analyticsData.executionTimeTrend.map((x: any) => x.executionTimeMs || 1),
                        );
                        const height = Math.max(4, (t.executionTimeMs / maxTime) * 80);
                        return (
                          <div
                            key={idx}
                            className="bg-primary/60 rounded-t flex-1 min-w-[4px]"
                            style={{ height: `${height}px` }}
                            title={`${(t.executionTimeMs / 1000).toFixed(1)}s`}
                          />
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <BarChart3 className="h-8 w-8 mb-2" />
                <p className="text-sm">No analytics data available</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ─── 20.9 Notifications Tab ──────────────────────────────────────── */}
        <TabsContent value="notifications" className="mt-4 space-y-4" data-testid="tab-content-notifications">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Notification Channel Templates</CardTitle>
              <CardDescription className="text-xs">
                Configure notification templates for playbook steps — supports email, Slack, Teams, PagerDuty, and
                webhook
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Select Playbook</Label>
                  <Select value={selectedNotifPlaybookId || ""} onValueChange={(v) => setSelectedNotifPlaybookId(v)}>
                    <SelectTrigger data-testid="select-notif-playbook">
                      <SelectValue placeholder="Choose a playbook..." />
                    </SelectTrigger>
                    <SelectContent>
                      {(playbooks || []).map((pb) => (
                        <SelectItem key={pb.id} value={String(pb.id)}>
                          {pb.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {selectedNotifPlaybookId && (
                  <>
                    <Separator />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <Label className="text-xs">Channel</Label>
                        <Select value={notifChannel} onValueChange={setNotifChannel}>
                          <SelectTrigger data-testid="select-notif-channel">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="email">Email</SelectItem>
                            <SelectItem value="slack">Slack</SelectItem>
                            <SelectItem value="teams">Microsoft Teams</SelectItem>
                            <SelectItem value="pagerduty">PagerDuty</SelectItem>
                            <SelectItem value="webhook">Webhook</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-1.5">
                        <Label className="text-xs">Subject / Title</Label>
                        <Input
                          placeholder="Alert: {{severity}} incident detected"
                          value={notifSubject}
                          onChange={(e) => setNotifSubject(e.target.value)}
                          data-testid="input-notif-subject"
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Body Template</Label>
                      <Textarea
                        placeholder="Incident {{incident_id}} — {{title}} (Severity: {{severity}}) triggered at {{timestamp}}"
                        value={notifBody}
                        onChange={(e) => setNotifBody(e.target.value)}
                        className="resize-none text-xs"
                        rows={3}
                        data-testid="input-notif-body"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Recipients / Channel / Webhook URL</Label>
                      <Input
                        placeholder={
                          notifChannel === "email"
                            ? "user@example.com"
                            : notifChannel === "webhook"
                              ? "https://..."
                              : "#channel"
                        }
                        value={notifRecipients}
                        onChange={(e) => setNotifRecipients(e.target.value)}
                        data-testid="input-notif-recipients"
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        onClick={() => {
                          if (!notifBody.trim()) return;
                          createNotifTemplateMutation.mutate({
                            channel: notifChannel,
                            subject: notifSubject || null,
                            body: notifBody,
                            recipients: notifRecipients || null,
                            webhookUrl: notifChannel === "webhook" ? notifRecipients : null,
                          });
                        }}
                        disabled={!notifBody.trim() || createNotifTemplateMutation.isPending}
                        data-testid="button-create-notif-template"
                      >
                        {createNotifTemplateMutation.isPending ? (
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                          <Plus className="h-4 w-4 mr-2" />
                        )}
                        Create Template
                      </Button>
                    </div>

                    {/* Available Variables */}
                    {notifConfig?.availableChannels && (
                      <div className="text-xs text-muted-foreground">
                        <span className="font-medium">Available variables: </span>
                        {notifConfig.availableChannels
                          .find((c: any) => c.channel === notifChannel)
                          ?.variables?.join(", ") || "—"}
                      </div>
                    )}

                    {/* Existing Templates */}
                    {notifConfig?.templates && notifConfig.templates.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                          Existing Templates
                        </h4>
                        {notifConfig.templates.map((t: any) => (
                          <div
                            key={t.id}
                            className="flex items-start justify-between p-2.5 bg-muted/10 rounded text-xs gap-2"
                          >
                            <div className="flex-1 min-w-0 space-y-1">
                              <div className="flex items-center gap-2">
                                <Badge
                                  variant="outline"
                                  className="text-[10px] no-default-hover-elevate no-default-active-elevate"
                                >
                                  {t.channel}
                                </Badge>
                                {t.subject && <span className="font-medium truncate">{t.subject}</span>}
                              </div>
                              <p className="text-muted-foreground truncate">{t.body}</p>
                              <p className="text-muted-foreground/60">
                                by {t.createdBy} • {t.createdAt ? formatDateShort(new Date(t.createdAt)) : "—"}
                              </p>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0"
                              onClick={() => deleteNotifTemplateMutation.mutate(t.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── 20.10 Change Management Tab ─────────────────────────────────── */}
        <TabsContent value="changes" className="mt-4 space-y-4" data-testid="tab-content-changes">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Create Change Ticket</CardTitle>
              <CardDescription className="text-xs">
                Track infrastructure changes made by playbook executions
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Playbook</Label>
                  <Select value={changePlaybookId} onValueChange={setChangePlaybookId}>
                    <SelectTrigger data-testid="select-change-playbook">
                      <SelectValue placeholder="Select playbook..." />
                    </SelectTrigger>
                    <SelectContent>
                      {(playbooks || []).map((pb) => (
                        <SelectItem key={pb.id} value={String(pb.id)}>
                          {pb.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Change Type</Label>
                  <Select value={changeType} onValueChange={setChangeType}>
                    <SelectTrigger data-testid="select-change-type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="firewall_rule">Firewall Rule</SelectItem>
                      <SelectItem value="account_disable">Account Disable</SelectItem>
                      <SelectItem value="network_block">Network Block</SelectItem>
                      <SelectItem value="endpoint_isolation">Endpoint Isolation</SelectItem>
                      <SelectItem value="detection_update">Detection Update</SelectItem>
                      <SelectItem value="configuration_change">Configuration Change</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Summary</Label>
                  <Input
                    placeholder="Brief summary of the change..."
                    value={changeSummary}
                    onChange={(e) => setChangeSummary(e.target.value)}
                    data-testid="input-change-summary"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Description (optional)</Label>
                <Textarea
                  placeholder="Detailed description of the change and its impact..."
                  value={changeDesc}
                  onChange={(e) => setChangeDesc(e.target.value)}
                  className="resize-none text-xs"
                  rows={2}
                  data-testid="input-change-desc"
                />
              </div>
              <Button
                size="sm"
                onClick={() => {
                  if (!changePlaybookId || !changeSummary.trim()) return;
                  createChangeTicketMutation.mutate({
                    playbookId: Number(changePlaybookId),
                    changeType,
                    summary: changeSummary,
                    description: changeDesc || null,
                  });
                }}
                disabled={!changePlaybookId || !changeSummary.trim() || createChangeTicketMutation.isPending}
                data-testid="button-create-change-ticket"
              >
                {createChangeTicketMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Ticket className="h-4 w-4 mr-2" />
                )}
                Create Change Ticket
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Change Tickets</CardTitle>
              <CardDescription className="text-xs">{changeTickets?.total ?? 0} tickets tracked</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-80">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">ID</TableHead>
                      <TableHead className="text-xs">Playbook</TableHead>
                      <TableHead className="text-xs">Type</TableHead>
                      <TableHead className="text-xs">Summary</TableHead>
                      <TableHead className="text-xs">Status</TableHead>
                      <TableHead className="text-xs">Requested</TableHead>
                      <TableHead className="text-xs">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(changeTickets?.tickets || []).map((ticket: any) => (
                      <TableRow key={ticket.id}>
                        <TableCell className="text-xs font-mono">{ticket.id}</TableCell>
                        <TableCell className="text-xs">{ticket.playbookName}</TableCell>
                        <TableCell className="text-xs">
                          <Badge
                            variant="outline"
                            className="text-[10px] no-default-hover-elevate no-default-active-elevate"
                          >
                            {ticket.changeType?.replace(/_/g, " ")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs max-w-[200px] truncate">{ticket.summary}</TableCell>
                        <TableCell className="text-xs">
                          <Badge
                            variant={
                              ticket.status === "approved" || ticket.status === "implemented"
                                ? "default"
                                : ticket.status === "rejected"
                                  ? "destructive"
                                  : ticket.status === "closed"
                                    ? "outline"
                                    : "secondary"
                            }
                            className="text-[10px]"
                          >
                            {ticket.status?.replace(/_/g, " ")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {ticket.requestedBy}
                          <br />
                          {ticket.requestedAt ? formatDateShort(new Date(ticket.requestedAt)) : "—"}
                        </TableCell>
                        <TableCell className="text-xs">
                          <div className="flex items-center gap-1">
                            {ticket.status === "pending_approval" && (
                              <>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="h-6 text-[10px]"
                                  onClick={() =>
                                    approveChangeTicketMutation.mutate({ ticketId: ticket.id, decision: "approved" })
                                  }
                                >
                                  Approve
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="h-6 text-[10px]"
                                  onClick={() =>
                                    approveChangeTicketMutation.mutate({ ticketId: ticket.id, decision: "rejected" })
                                  }
                                >
                                  Reject
                                </Button>
                              </>
                            )}
                            {ticket.status === "approved" && (
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-6 text-[10px]"
                                onClick={() => implementChangeTicketMutation.mutate(ticket.id)}
                              >
                                Implement
                              </Button>
                            )}
                            {(ticket.status === "implemented" || ticket.status === "approved") && (
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 text-[10px]"
                                onClick={() => closeChangeTicketMutation.mutate(ticket.id)}
                              >
                                Close
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!(changeTickets?.tickets || []).length && (
                      <TableRow>
                        <TableCell colSpan={7} className="text-center text-xs text-muted-foreground py-8">
                          No change tickets yet. Create one above to track infrastructure changes.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={showVersionDialog} onOpenChange={setShowVersionDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create Version Snapshot</DialogTitle>
            <DialogDescription>Snapshot the current playbook state as a new version</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Changelog</Label>
              <Textarea
                value={versionChangelog}
                onChange={(e) => setVersionChangelog(e.target.value)}
                placeholder="What changed in this version..."
                data-testid="input-version-changelog"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setShowVersionDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (selectedGovernancePlaybook)
                  createVersionMutation.mutate({ playbookId: selectedGovernancePlaybook, changelog: versionChangelog });
              }}
              disabled={createVersionMutation.isPending}
              data-testid="button-submit-version"
            >
              {createVersionMutation.isPending ? "Creating..." : "Create Version"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={showSimulationDialog} onOpenChange={setShowSimulationDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Run Simulation</DialogTitle>
            <DialogDescription>Execute a dry run of the playbook without making real changes</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Parameters (JSON, optional)</Label>
              <Textarea
                value={simParams}
                onChange={(e) => setSimParams(e.target.value)}
                placeholder='{"alertId": "test-123"}'
                className="font-mono text-xs"
                data-testid="input-sim-params"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setShowSimulationDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (selectedGovernancePlaybook) {
                  let params: Record<string, unknown> | undefined;
                  if (simParams.trim()) {
                    try {
                      params = JSON.parse(simParams);
                    } catch {
                      params = { raw: simParams };
                    }
                  }
                  runSimulationMutation.mutate({ playbookId: selectedGovernancePlaybook, parameters: params });
                }
              }}
              disabled={runSimulationMutation.isPending}
              data-testid="button-submit-simulation"
            >
              {runSimulationMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Beaker className="h-4 w-4 mr-2" />
              )}
              Run Simulation
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={showBlastRadiusDialog} onOpenChange={setShowBlastRadiusDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Generate Blast Radius Preview</DialogTitle>
            <DialogDescription>See what resources would be affected before executing the playbook</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Trigger Context (JSON, optional)</Label>
              <Textarea
                value={blastRadiusContext}
                onChange={(e) => setBlastRadiusContext(e.target.value)}
                placeholder='{"targetIp": "10.0.0.1"}'
                className="font-mono text-xs"
                data-testid="input-blast-context"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setShowBlastRadiusDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (selectedGovernancePlaybook) {
                  let ctx: Record<string, unknown> | undefined;
                  if (blastRadiusContext.trim()) {
                    try {
                      ctx = JSON.parse(blastRadiusContext);
                    } catch {
                      ctx = { raw: blastRadiusContext };
                    }
                  }
                  createBlastRadiusMutation.mutate({ playbookId: selectedGovernancePlaybook, triggerContext: ctx });
                }
              }}
              disabled={createBlastRadiusMutation.isPending}
              data-testid="button-submit-blast-radius"
            >
              {createBlastRadiusMutation.isPending ? "Generating..." : "Generate Preview"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={showRollbackPlanDialog} onOpenChange={setShowRollbackPlanDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create Rollback Plan</DialogTitle>
            <DialogDescription>Define steps to safely reverse the playbook actions</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Description</Label>
              <Input
                value={rollbackPlanDesc}
                onChange={(e) => setRollbackPlanDesc(e.target.value)}
                placeholder="Rollback plan for..."
                data-testid="input-rollback-desc"
              />
            </div>
            <div className="space-y-2">
              <Label>Steps (one per line)</Label>
              <Textarea
                value={rollbackSteps}
                onChange={(e) => setRollbackSteps(e.target.value)}
                placeholder="Step 1: Remove firewall rule\nStep 2: Re-enable user account"
                data-testid="input-rollback-steps"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setShowRollbackPlanDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (selectedGovernancePlaybook && rollbackPlanDesc.trim()) {
                  const steps = rollbackSteps
                    .split("\n")
                    .map((s) => s.trim())
                    .filter(Boolean);
                  createRollbackPlanMutation.mutate({
                    playbookId: selectedGovernancePlaybook,
                    description: rollbackPlanDesc,
                    steps,
                  });
                }
              }}
              disabled={!rollbackPlanDesc.trim() || createRollbackPlanMutation.isPending}
              data-testid="button-submit-rollback-plan"
            >
              {createRollbackPlanMutation.isPending ? "Creating..." : "Create Plan"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!executeDialogId}
        onOpenChange={(open) => {
          if (!open) {
            setExecuteDialogId(null);
            setExecuteDryRun(false);
            setBlastRadiusConfirmed(false);
          }
        }}
      >
        <DialogContent className="max-w-lg" data-testid="dialog-execute">
          <DialogHeader>
            <DialogTitle>Execute Playbook</DialogTitle>
            <DialogDescription>
              Configure execution options for{" "}
              {playbooks?.find((p) => p.id === executeDialogId)?.name || "this playbook"}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {/* Blast Radius Preview */}
            {executeBlastRadiusQuery.isLoading ? (
              <div className="rounded-md border p-4 space-y-2">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Calculating blast radius...
                </div>
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-4 w-1/2" />
              </div>
            ) : executeBlastRadiusQuery.data ? (
              <div
                className={`rounded-md border p-4 space-y-3 ${
                  executeBlastRadiusQuery.data.riskLevel === "critical"
                    ? "border-red-500/50 bg-red-500/5"
                    : executeBlastRadiusQuery.data.riskLevel === "high"
                      ? "border-orange-500/50 bg-orange-500/5"
                      : executeBlastRadiusQuery.data.riskLevel === "medium"
                        ? "border-yellow-500/50 bg-yellow-500/5"
                        : "border-green-500/50 bg-green-500/5"
                }`}
                data-testid="blast-radius-preview"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Target className="h-4 w-4" />
                    <span className="text-sm font-medium">Blast Radius Preview</span>
                  </div>
                  <Badge
                    variant={
                      executeBlastRadiusQuery.data.riskLevel === "critical" ||
                      executeBlastRadiusQuery.data.riskLevel === "high"
                        ? "destructive"
                        : "outline"
                    }
                  >
                    {executeBlastRadiusQuery.data.riskLevel} risk
                  </Badge>
                </div>

                <div className="text-xs space-y-1">
                  <p>
                    <span className="font-medium">{executeBlastRadiusQuery.data.affectedEntityCount}</span> entities
                    affected &middot; Est. {Math.ceil((executeBlastRadiusQuery.data.estimatedDurationMs || 0) / 1000)}s
                    duration
                  </p>
                  {executeBlastRadiusQuery.data.reversible === false && (
                    <p className="text-red-400 font-medium flex items-center gap-1">
                      <AlertTriangle className="h-3 w-3" /> Contains irreversible actions
                    </p>
                  )}
                </div>

                {Array.isArray(executeBlastRadiusQuery.data.affectedEntities) &&
                  executeBlastRadiusQuery.data.affectedEntities.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs font-medium text-muted-foreground">Affected entities:</p>
                      <div className="space-y-0.5">
                        {(
                          executeBlastRadiusQuery.data.affectedEntities as Array<{
                            type: string;
                            identifier: string;
                            impact: string;
                          }>
                        )
                          .slice(0, 5)
                          .map((entity, idx) => (
                            <div key={idx} className="text-xs flex items-center gap-2 rounded px-2 py-0.5 bg-muted/50">
                              <Badge variant="outline" className="text-[10px] px-1 py-0">
                                {entity.type}
                              </Badge>
                              <span className="truncate">{entity.identifier}</span>
                              <span className="text-muted-foreground ml-auto shrink-0">{entity.impact}</span>
                            </div>
                          ))}
                        {(
                          executeBlastRadiusQuery.data.affectedEntities as Array<{
                            type: string;
                            identifier: string;
                            impact: string;
                          }>
                        ).length > 5 && (
                          <p className="text-xs text-muted-foreground pl-2">
                            +
                            {(
                              executeBlastRadiusQuery.data.affectedEntities as Array<{
                                type: string;
                                identifier: string;
                                impact: string;
                              }>
                            ).length - 5}{" "}
                            more
                          </p>
                        )}
                      </div>
                    </div>
                  )}

                {Array.isArray(executeBlastRadiusQuery.data.riskFactors) &&
                  executeBlastRadiusQuery.data.riskFactors.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs font-medium text-muted-foreground">Risk factors:</p>
                      {(executeBlastRadiusQuery.data.riskFactors as string[]).map((rf, idx) => (
                        <p key={idx} className="text-xs text-yellow-500 flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3 shrink-0" /> {rf}
                        </p>
                      ))}
                    </div>
                  )}

                {/* Explicit confirmation checkbox */}
                <div className="flex items-center gap-2 pt-1 border-t border-muted">
                  <input
                    type="checkbox"
                    id="blast-radius-confirm"
                    checked={blastRadiusConfirmed}
                    onChange={(e) => setBlastRadiusConfirmed(e.target.checked)}
                    className="h-4 w-4 rounded border-muted-foreground"
                    data-testid="checkbox-blast-confirm"
                  />
                  <label htmlFor="blast-radius-confirm" className="text-xs">
                    I have reviewed the blast radius and accept the risk
                  </label>
                </div>
              </div>
            ) : null}

            <div className="flex items-center justify-between gap-4">
              <div>
                <Label className="text-sm font-medium">Dry Run Mode</Label>
                <p className="text-xs text-muted-foreground mt-0.5">Simulate execution without taking real actions</p>
              </div>
              <Switch checked={executeDryRun} onCheckedChange={setExecuteDryRun} data-testid="switch-dry-run" />
            </div>
            {executeDryRun && (
              <div className="rounded-md bg-cyan-500/10 p-3">
                <p className="text-xs text-cyan-400">
                  Actions will be logged but not executed. No changes will be made to your environment.
                </p>
              </div>
            )}
          </div>
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setExecuteDialogId(null);
                setExecuteDryRun(false);
                setBlastRadiusConfirmed(false);
              }}
              data-testid="button-cancel-execute"
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (executeDialogId) {
                  executeMutation.mutate({ id: executeDialogId, dryRun: executeDryRun });
                }
              }}
              disabled={
                executeMutation.isPending ||
                executeBlastRadiusQuery.isLoading ||
                (!blastRadiusConfirmed && !executeDryRun && !!executeBlastRadiusQuery.data)
              }
              data-testid="button-confirm-execute"
            >
              {executeMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Play className="h-4 w-4 mr-2" />
              )}
              {executeDryRun ? "Dry Run" : "Run"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={showDialog}
        onOpenChange={(open) => {
          if (!open) closeDialog();
          else setShowDialog(true);
        }}
      >
        <DialogContent className="max-w-5xl max-h-[85vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>{editingPlaybook ? "Edit Playbook" : "Create Playbook"}</DialogTitle>
            <DialogDescription>
              {editingPlaybook
                ? "Update your automation playbook with the visual builder."
                : "Build a new automated response workflow visually."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs">Name</Label>
              <Input
                placeholder="e.g. Critical Alert Auto-Triage"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                data-testid="input-playbook-name"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Trigger</Label>
              <Select value={formTrigger} onValueChange={setFormTrigger}>
                <SelectTrigger data-testid="select-trigger">
                  <SelectValue placeholder="Select trigger..." />
                </SelectTrigger>
                <SelectContent>
                  {TRIGGER_OPTIONS.map((t) => (
                    <SelectItem key={t.value} value={t.value} data-testid={`option-trigger-${t.value}`}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Status</Label>
              <Select value={formStatus} onValueChange={setFormStatus}>
                <SelectTrigger data-testid="select-status">
                  <SelectValue placeholder="Status..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="draft" data-testid="option-status-draft">
                    Draft
                  </SelectItem>
                  <SelectItem value="active" data-testid="option-status-active">
                    Active
                  </SelectItem>
                  <SelectItem value="inactive" data-testid="option-status-inactive">
                    Inactive
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description</Label>
              <Input
                placeholder="What does this playbook do?"
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                data-testid="input-playbook-description"
              />
            </div>
          </div>

          <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
            <VisualBuilder
              nodes={flowNodes}
              setNodes={setFlowNodes}
              selectedNodeId={selectedNodeId}
              setSelectedNodeId={setSelectedNodeId}
            />
          </div>

          <div className="flex items-center justify-between gap-4 pt-2 flex-wrap">
            <div className="text-xs text-muted-foreground">{flowNodes.length} nodes in flow</div>
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={closeDialog} data-testid="button-cancel">
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={createMutation.isPending || updateMutation.isPending}
                data-testid="button-save-playbook"
              >
                {createMutation.isPending || updateMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <CheckCircle className="h-4 w-4 mr-2" />
                )}
                {editingPlaybook ? "Update Playbook" : "Create Playbook"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
