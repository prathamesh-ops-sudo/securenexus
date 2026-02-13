import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
} from "lucide-react";
import type { Playbook, PlaybookExecution } from "@shared/schema";

interface FlowNode {
  id: string;
  type: "trigger" | "action" | "condition";
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

const TRIGGER_OPTIONS = [
  { value: "alert_created", label: "Alert Created" },
  { value: "alert_critical", label: "Alert Critical" },
  { value: "incident_created", label: "Incident Created" },
  { value: "incident_escalated", label: "Incident Escalated" },
  { value: "manual", label: "Manual" },
] as const;

function formatRelativeTime(date: string | Date | null | undefined): string {
  if (!date) return "Never";
  const now = Date.now();
  const then = new Date(date).getTime();
  const diffMs = now - then;
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;
  return new Date(date).toLocaleDateString();
}

function triggerLabel(trigger: string): string {
  return TRIGGER_OPTIONS.find(t => t.value === trigger)?.label || trigger;
}

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return <Badge variant="default" data-testid={`badge-status-${status}`}><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>;
    case "draft":
      return <Badge variant="secondary" data-testid={`badge-status-${status}`}><Pencil className="h-3 w-3 mr-1" />Draft</Badge>;
    case "inactive":
      return <Badge variant="outline" data-testid={`badge-status-${status}`}>Inactive</Badge>;
    default:
      return <Badge variant="outline" data-testid={`badge-status-${status}`}>{status}</Badge>;
  }
}

function executionStatusBadge(status: string) {
  switch (status) {
    case "completed":
      return <Badge variant="default" data-testid={`badge-exec-status-${status}`}><CheckCircle className="h-3 w-3 mr-1" />Completed</Badge>;
    case "running":
      return <Badge variant="secondary" data-testid={`badge-exec-status-${status}`}><Loader2 className="h-3 w-3 mr-1 animate-spin" />Running</Badge>;
    case "failed":
      return <Badge variant="destructive" data-testid={`badge-exec-status-${status}`}><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
    default:
      return <Badge variant="outline" data-testid={`badge-exec-status-${status}`}>{status}</Badge>;
  }
}

function getNodeIcon(node: FlowNode) {
  if (node.type === "trigger") {
    const found = PALETTE_TRIGGERS.find(t => t.value === node.data.trigger);
    return found ? found.icon : Bell;
  }
  if (node.type === "action") {
    const found = PALETTE_ACTIONS.find(a => a.value === node.data.actionType);
    return found ? found.icon : Settings;
  }
  if (node.type === "condition") {
    const found = PALETTE_CONDITIONS.find(c => c.value === node.data.conditionType);
    return found ? found.icon : Eye;
  }
  return Settings;
}

function getNodeBorderColor(type: string) {
  switch (type) {
    case "trigger": return "border-l-blue-500";
    case "action": return "border-l-green-500";
    case "condition": return "border-l-orange-500";
    default: return "border-l-muted-foreground";
  }
}

function getNodeTypeBadge(type: string) {
  switch (type) {
    case "trigger": return <Badge variant="outline" className="text-[10px] no-default-hover-elevate no-default-active-elevate border-blue-500/40 text-blue-400">Trigger</Badge>;
    case "action": return <Badge variant="outline" className="text-[10px] no-default-hover-elevate no-default-active-elevate border-green-500/40 text-green-400">Action</Badge>;
    case "condition": return <Badge variant="outline" className="text-[10px] no-default-hover-elevate no-default-active-elevate border-orange-500/40 text-orange-400">Condition</Badge>;
    default: return null;
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

  if (node.type === "condition") {
    const condType = node.data.conditionType;
    return (
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Condition Configuration</h4>
        {condType === "severity_check" && (
          <div className="space-y-1.5">
            <Label className="text-xs">Severity</Label>
            <Select value={config.severity || ""} onValueChange={v => updateField("severity", v)}>
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
              onChange={e => updateField("source", e.target.value)}
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
                onChange={e => updateField("startHour", e.target.value)}
                data-testid="config-start-hour"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">End Hour (0-23)</Label>
              <Input
                type="number"
                placeholder="23"
                value={config.endHour || ""}
                onChange={e => updateField("endHour", e.target.value)}
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
            onChange={e => updateField("channel", e.target.value)}
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
            onChange={e => updateField("recipients", e.target.value)}
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
            onChange={e => updateField("webhookUrl", e.target.value)}
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
            onChange={e => updateField("analyst", e.target.value)}
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
            onChange={e => updateField("status", e.target.value)}
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
            onChange={e => updateField("tag", e.target.value)}
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
            onChange={e => updateField("duration", e.target.value)}
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
              onChange={e => updateField("project", e.target.value)}
              data-testid="config-project"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Priority</Label>
            <Input
              placeholder="high"
              value={config.priority || ""}
              onChange={e => updateField("priority", e.target.value)}
              data-testid="config-priority"
            />
          </div>
        </>
      )}
      {!["notify_slack", "notify_teams", "notify_email", "notify_webhook", "assign_analyst", "change_status", "add_tag", "block_ip", "block_domain", "create_jira_ticket", "create_servicenow_ticket"].includes(actionType || "") && (
        <div className="space-y-1.5">
          <Label className="text-xs">Parameters</Label>
          <Input
            placeholder="Additional config..."
            value={config.params || ""}
            onChange={e => updateField("params", e.target.value)}
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
  const parts = Object.entries(cfg).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`);
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
  const addNode = useCallback((type: "trigger" | "action" | "condition", value: string, label: string) => {
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
  }, [nodes, setNodes, setSelectedNodeId]);

  const removeNode = useCallback((id: string) => {
    setNodes(nodes.filter(n => n.id !== id));
    if (selectedNodeId === id) setSelectedNodeId(null);
  }, [nodes, setNodes, selectedNodeId, setSelectedNodeId]);

  const moveNode = useCallback((idx: number, dir: -1 | 1) => {
    const newIdx = idx + dir;
    if (newIdx < 0 || newIdx >= nodes.length) return;
    const updated = [...nodes];
    [updated[idx], updated[newIdx]] = [updated[newIdx], updated[idx]];
    setNodes(updated);
  }, [nodes, setNodes]);

  const updateNodeConfig = useCallback((id: string, config: Record<string, string>) => {
    setNodes(nodes.map(n => n.id === id ? { ...n, data: { ...n.data, config } } : n));
  }, [nodes, setNodes]);

  const selectedNode = nodes.find(n => n.id === selectedNodeId);

  return (
    <div className="flex gap-4 flex-1 min-h-0">
      <div className="w-52 flex-shrink-0 overflow-y-auto space-y-4" data-testid="panel-palette">
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Triggers</h4>
          <div className="space-y-1">
            {PALETTE_TRIGGERS.map(t => {
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
            {PALETTE_ACTIONS.map(a => {
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
            {PALETTE_CONDITIONS.map(c => {
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
                        {summary && (
                          <p className="text-xs text-muted-foreground mt-0.5 truncate">{summary}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-0.5 flex-shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={e => { e.stopPropagation(); moveNode(idx, -1); }}
                          disabled={idx === 0}
                          data-testid={`button-move-up-${node.id}`}
                        >
                          <ArrowUp className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={e => { e.stopPropagation(); moveNode(idx, 1); }}
                          disabled={idx === nodes.length - 1}
                          data-testid={`button-move-down-${node.id}`}
                        >
                          <ArrowDown className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={e => { e.stopPropagation(); removeNode(node.id); }}
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
              <NodeConfigPanel
                node={selectedNode}
                onUpdate={(config) => updateNodeConfig(selectedNode.id, config)}
              />
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

  const { data: playbooks, isLoading: playbooksLoading } = useQuery<Playbook[]>({
    queryKey: ["/api/playbooks"],
  });

  const { data: executions, isLoading: executionsLoading } = useQuery<(PlaybookExecution & { playbookName?: string })[]>({
    queryKey: ["/api/playbook-executions"],
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
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/playbooks/${id}/execute`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-executions"] });
      toast({ title: "Playbook executed", description: "Manual execution started." });
    },
    onError: (err: any) => {
      toast({ title: "Execution failed", description: err.message, variant: "destructive" });
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
      toast({ title: "Missing required fields", description: "Name and trigger are required.", variant: "destructive" });
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

  const activeCount = playbooks?.filter(p => p.status === "active").length || 0;
  const totalExecutions = playbooks?.reduce((sum, p) => sum + (p.triggerCount || 0), 0) || 0;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Automation Playbooks</span></h1>
          <p className="text-sm text-muted-foreground">Create and manage automated response workflows for security events</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Button onClick={openCreate} data-testid="button-create-playbook">
          <Plus className="h-4 w-4 mr-2" />
          Create Playbook
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Playbooks</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {playbooksLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="text-total-playbooks">{playbooks?.length || 0}</div>
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
              <div className="text-2xl font-bold" data-testid="text-active-playbooks">{activeCount}</div>
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
              <div className="text-2xl font-bold" data-testid="text-total-executions">{totalExecutions}</div>
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
          <TabsTrigger value="history" data-testid="tab-history">
            <Activity className="h-4 w-4 mr-1.5" />
            Execution History
          </TabsTrigger>
        </TabsList>

        <TabsContent value="playbooks" className="mt-4">
          {playbooksLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map(i => (
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
              {playbooks.map(pb => {
                const flow = parseFlowFromActions(pb.actions);
                const nodeCount = flow.nodes.length;
                return (
                  <Card key={pb.id} className="hover-elevate" data-testid={`card-playbook-${pb.id}`}>
                    <CardContent className="p-5 space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <h3 className="font-semibold text-sm truncate" data-testid={`text-playbook-name-${pb.id}`}>{pb.name}</h3>
                          {pb.description && (
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-2" data-testid={`text-playbook-desc-${pb.id}`}>{pb.description}</p>
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
                          onClick={() => executeMutation.mutate(pb.id)}
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

        <TabsContent value="history" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Execution History</CardTitle>
              <CardDescription>Recent playbook execution results</CardDescription>
            </CardHeader>
            <CardContent>
              {executionsLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3].map(i => (
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
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {executions.map(exec => {
                      const pb = playbooks?.find(p => p.id === exec.playbookId);
                      return (
                        <TableRow key={exec.id} data-testid={`row-execution-${exec.id}`}>
                          <TableCell>{executionStatusBadge(exec.status)}</TableCell>
                          <TableCell>
                            <span className="font-medium text-sm" data-testid={`text-exec-playbook-${exec.id}`}>
                              {exec.playbookName || pb?.name || "Unknown"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="text-sm text-muted-foreground" data-testid={`text-exec-triggered-by-${exec.id}`}>
                              {exec.triggeredBy || "System"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="text-sm text-muted-foreground" data-testid={`text-exec-resource-${exec.id}`}>
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
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={showDialog} onOpenChange={(open) => { if (!open) closeDialog(); else setShowDialog(true); }}>
        <DialogContent className="max-w-5xl max-h-[85vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>{editingPlaybook ? "Edit Playbook" : "Create Playbook"}</DialogTitle>
            <DialogDescription>
              {editingPlaybook ? "Update your automation playbook with the visual builder." : "Build a new automated response workflow visually."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs">Name</Label>
              <Input
                placeholder="e.g. Critical Alert Auto-Triage"
                value={formName}
                onChange={e => setFormName(e.target.value)}
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
                  {TRIGGER_OPTIONS.map(t => (
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
                  <SelectItem value="draft" data-testid="option-status-draft">Draft</SelectItem>
                  <SelectItem value="active" data-testid="option-status-active">Active</SelectItem>
                  <SelectItem value="inactive" data-testid="option-status-inactive">Inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description</Label>
              <Input
                placeholder="What does this playbook do?"
                value={formDescription}
                onChange={e => setFormDescription(e.target.value)}
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
            <div className="text-xs text-muted-foreground">
              {flowNodes.length} nodes in flow
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={closeDialog} data-testid="button-cancel">
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={createMutation.isPending || updateMutation.isPending}
                data-testid="button-save-playbook"
              >
                {(createMutation.isPending || updateMutation.isPending) ? (
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
