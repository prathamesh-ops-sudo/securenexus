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
} from "lucide-react";
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
      const res = await fetch(`/api/playbooks/${selectedGovernancePlaybook}/versions`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to load versions");
      const body = await res.json();
      return body.data ?? body;
    },
    enabled: !!selectedGovernancePlaybook,
  });

  const { data: simulations, isLoading: simulationsLoading } = useQuery<PlaybookSimulation[]>({
    queryKey: ["/api/playbooks", selectedGovernancePlaybook, "simulations"],
    queryFn: async () => {
      const res = await fetch(`/api/playbooks/${selectedGovernancePlaybook}/simulations`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to load simulations");
      const body = await res.json();
      return body.data ?? body;
    },
    enabled: !!selectedGovernancePlaybook,
  });

  const { data: blastPreviews, isLoading: blastLoading } = useQuery<BlastRadiusPreview[]>({
    queryKey: ["/api/playbooks", selectedGovernancePlaybook, "blast-radius"],
    queryFn: async () => {
      const res = await fetch(`/api/playbooks/${selectedGovernancePlaybook}/blast-radius`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to load blast radius");
      const body = await res.json();
      return body.data ?? body;
    },
    enabled: !!selectedGovernancePlaybook,
  });

  const { data: rollbackPlans, isLoading: rollbackPlansLoading } = useQuery<PlaybookRollbackPlan[]>({
    queryKey: ["/api/playbooks", selectedGovernancePlaybook, "rollback-plans"],
    queryFn: async () => {
      const res = await fetch(`/api/playbooks/${selectedGovernancePlaybook}/rollback-plans`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to load rollback plans");
      const body = await res.json();
      return body.data ?? body;
    },
    enabled: !!selectedGovernancePlaybook,
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
            </Tabs>
          )}
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
          }
        }}
      >
        <DialogContent className="max-w-md" data-testid="dialog-execute">
          <DialogHeader>
            <DialogTitle>Execute Playbook</DialogTitle>
            <DialogDescription>
              Configure execution options for{" "}
              {playbooks?.find((p) => p.id === executeDialogId)?.name || "this playbook"}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
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
              disabled={executeMutation.isPending}
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
