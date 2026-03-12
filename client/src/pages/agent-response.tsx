import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import {
  Zap,
  Shield,
  Server,
  Wifi,
  WifiOff,
  Trash2,
  StopCircle,
  Network,
  Terminal,
  UserX,
  FolderX,
  RotateCcw,
  HardDrive,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  Plus,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  ShieldAlert,
  Play,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ResponseAction {
  id: string;
  sensorId: string;
  hostname?: string;
  actionType: string;
  params: Record<string, unknown>;
  status: string;
  triggeredBy: string;
  triggeredByAlertId?: string;
  triggeredByIncidentId?: string;
  requiresApproval: boolean;
  approvedBy?: string;
  approvedAt?: string;
  completedAt?: string;
  resultOutput?: string;
  errorMessage?: string;
  timeoutAt?: string;
  createdAt: string;
}

interface ActionStats {
  byStatus: Record<string, number>;
  byType: Record<string, number>;
  recentCompletions: number;
}

interface NativeSensor {
  id: string;
  hostname: string;
  status: string;
  platform: string;
}

// ─── Config ───────────────────────────────────────────────────────────────────

const ACTION_CONFIGS: Record<string, {
  label: string;
  icon: React.ReactNode;
  color: string;
  risk: "high" | "medium" | "low";
  description: string;
  paramsSchema: Array<{ key: string; label: string; type: "text" | "textarea" | "select"; options?: string[] }>;
}> = {
  kill_process: {
    label: "Kill Process",
    icon: <StopCircle className="h-4 w-4" />,
    color: "text-red-400",
    risk: "medium",
    description: "Terminate a running process by PID or name",
    paramsSchema: [
      { key: "processName", label: "Process Name", type: "text" },
      { key: "pid", label: "PID (optional)", type: "text" },
    ],
  },
  isolate_host: {
    label: "Isolate Host",
    icon: <WifiOff className="h-4 w-4" />,
    color: "text-red-500",
    risk: "high",
    description: "Cut all network access except management channel",
    paramsSchema: [],
  },
  unisolate_host: {
    label: "Un-isolate Host",
    icon: <Wifi className="h-4 w-4" />,
    color: "text-emerald-400",
    risk: "medium",
    description: "Restore full network access",
    paramsSchema: [],
  },
  block_ip: {
    label: "Block IP",
    icon: <Network className="h-4 w-4" />,
    color: "text-orange-400",
    risk: "medium",
    description: "Block an IP via host firewall (iptables / Windows Firewall)",
    paramsSchema: [
      { key: "ip", label: "IP Address", type: "text" },
      { key: "direction", label: "Direction", type: "select", options: ["both", "inbound", "outbound"] },
    ],
  },
  unblock_ip: {
    label: "Unblock IP",
    icon: <Network className="h-4 w-4" />,
    color: "text-blue-400",
    risk: "low",
    description: "Remove IP firewall block",
    paramsSchema: [
      { key: "ip", label: "IP Address", type: "text" },
    ],
  },
  quarantine_file: {
    label: "Quarantine File",
    icon: <FolderX className="h-4 w-4" />,
    color: "text-orange-400",
    risk: "medium",
    description: "Move file to quarantine directory and strip permissions",
    paramsSchema: [
      { key: "filePath", label: "File Path", type: "text" },
    ],
  },
  delete_file: {
    label: "Delete File",
    icon: <Trash2 className="h-4 w-4" />,
    color: "text-red-400",
    risk: "high",
    description: "Permanently delete a file (requires approval)",
    paramsSchema: [
      { key: "filePath", label: "File Path", type: "text" },
    ],
  },
  disable_user: {
    label: "Disable User",
    icon: <UserX className="h-4 w-4" />,
    color: "text-red-400",
    risk: "high",
    description: "Lock the user account on this host (requires approval)",
    paramsSchema: [
      { key: "username", label: "Username", type: "text" },
    ],
  },
  collect_forensics: {
    label: "Collect Forensics",
    icon: <HardDrive className="h-4 w-4" />,
    color: "text-violet-400",
    risk: "low",
    description: "Collect memory/process/network snapshot for investigation",
    paramsSchema: [],
  },
  run_script: {
    label: "Run Script",
    icon: <Terminal className="h-4 w-4" />,
    color: "text-amber-400",
    risk: "high",
    description: "Execute a custom script on the sensor (requires approval)",
    paramsSchema: [
      { key: "interpreter", label: "Interpreter", type: "select", options: ["bash", "powershell", "cmd"] },
      { key: "script", label: "Script", type: "textarea" },
    ],
  },
  restart_service: {
    label: "Restart Service",
    icon: <RotateCcw className="h-4 w-4" />,
    color: "text-cyan-400",
    risk: "medium",
    description: "Restart a system service",
    paramsSchema: [
      { key: "serviceName", label: "Service Name", type: "text" },
    ],
  },
};

// ─── Status helpers ───────────────────────────────────────────────────────────

function statusIcon(status: string) {
  switch (status) {
    case "completed": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
    case "pending": return <Clock className="h-4 w-4 text-yellow-400" />;
    case "dispatched":
    case "acknowledged": return <RefreshCw className="h-4 w-4 text-cyan-400 animate-spin" />;
    case "cancelled":
    case "timeout": return <XCircle className="h-4 w-4 text-slate-500" />;
    default: return <Clock className="h-4 w-4 text-slate-400" />;
  }
}

function statusBadgeClass(status: string) {
  switch (status) {
    case "completed": return "border-emerald-500/30 text-emerald-400";
    case "failed": return "border-red-500/30 text-red-400";
    case "pending": return "border-yellow-500/30 text-yellow-400";
    case "dispatched":
    case "acknowledged": return "border-cyan-500/30 text-cyan-400";
    default: return "border-slate-600 text-slate-500";
  }
}

function formatRelative(ts?: string) {
  if (!ts) return "";
  const d = Date.now() - new Date(ts).getTime();
  if (d < 60_000) return "just now";
  if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`;
  return `${Math.floor(d / 3_600_000)}h ago`;
}

// ─── Action Row ───────────────────────────────────────────────────────────────

function ActionRow({ action, onApprove, onCancel }: {
  action: ResponseAction;
  onApprove: (id: string) => void;
  onCancel: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const cfg = ACTION_CONFIGS[action.actionType];

  return (
    <div className={`rounded-lg border ${
      action.status === "completed" ? "border-emerald-500/15 bg-slate-900/30" :
      action.status === "failed" ? "border-red-500/20 bg-red-950/10" :
      action.requiresApproval && action.status === "pending" ? "border-amber-500/30 bg-amber-950/10" :
      "border-slate-700/50 bg-slate-800/40"
    }`}>
      <div className="flex items-center gap-4 p-4 cursor-pointer" onClick={() => setExpanded((v) => !v)}>
        <div className={cfg?.color ?? "text-slate-400"}>
          {cfg?.icon ?? <Zap className="h-4 w-4" />}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-white">{cfg?.label ?? action.actionType}</span>
            {action.requiresApproval && action.status === "pending" && (
              <Badge variant="outline" className="text-xs border-amber-500/30 text-amber-400 px-1.5 py-0">
                Needs Approval
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500 mt-0.5">
            <Server className="h-3 w-3" />
            <span>{action.hostname ?? action.sensorId.slice(0, 8)}</span>
            <span>·</span>
            <span>{formatRelative(action.createdAt)}</span>
            {action.triggeredBy !== "manual" && (
              <>
                <span>·</span>
                <span className="capitalize">{action.triggeredBy.replace(/_/g, " ")}</span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {statusIcon(action.status)}
          <Badge variant="outline" className={`text-xs px-1.5 py-0 ${statusBadgeClass(action.status)}`}>
            {action.status}
          </Badge>
        </div>

        {action.requiresApproval && action.status === "pending" && (
          <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
            <Button
              size="sm"
              className="h-6 text-xs bg-emerald-700/50 hover:bg-emerald-700 text-emerald-300 px-2"
              onClick={() => onApprove(action.id)}
            >
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-6 text-xs border-slate-600 text-slate-400 hover:text-red-400 px-2"
              onClick={() => onCancel(action.id)}
            >
              Deny
            </Button>
          </div>
        )}

        {["pending", "dispatched"].includes(action.status) && !action.requiresApproval && (
          <Button
            size="sm"
            variant="ghost"
            className="h-6 w-6 p-0 text-slate-500 hover:text-red-400 shrink-0"
            onClick={(e) => { e.stopPropagation(); onCancel(action.id); }}
          >
            <XCircle className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/30 pt-3 space-y-2">
          {Object.keys(action.params).length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Parameters:</p>
              <pre className="text-xs text-slate-300 bg-slate-900 rounded p-2 font-mono overflow-x-auto">
                {JSON.stringify(action.params, null, 2)}
              </pre>
            </div>
          )}
          {action.resultOutput && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Output:</p>
              <pre className="text-xs text-emerald-300 bg-slate-900 rounded p-2 font-mono overflow-x-auto">
                {action.resultOutput}
              </pre>
            </div>
          )}
          {action.errorMessage && (
            <p className="text-xs text-red-400">{action.errorMessage}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Create Action Dialog ─────────────────────────────────────────────────────

function CreateActionDialog({ sensors }: { sensors: NativeSensor[] }) {
  const [open, setOpen] = useState(false);
  const [sensorId, setSensorId] = useState("");
  const [actionType, setActionType] = useState("kill_process");
  const [params, setParams] = useState<Record<string, string>>({});
  const { toast } = useToast();

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiRequest("POST", "/api/native/response/actions", body).then((r) => r.json()),
    onSuccess: (data) => {
      setOpen(false);
      setParams({});
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      const msg = data.data?.requiresApproval
        ? "Action queued — waiting for admin approval."
        : "Action dispatched to sensor.";
      toast({ title: "Response action created", description: msg });
    },
    onError: (err: any) =>
      toast({ title: "Failed to create action", description: err.message, variant: "destructive" }),
  });

  const cfg = ACTION_CONFIGS[actionType];

  function submit() {
    if (!sensorId) { toast({ title: "Select a sensor", variant: "destructive" }); return; }
    const cleanParams: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(params)) {
      if (v) cleanParams[k] = v;
    }
    createMutation.mutate({ sensorId, actionType, params: cleanParams });
  }

  return (
    <>
      <Button className="bg-cyan-600 hover:bg-cyan-700 text-white gap-2" onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" />
        New Action
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="bg-slate-900 border-slate-700 max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-white">Create Response Action</DialogTitle>
            <DialogDescription className="text-slate-400">
              Push a remediation command directly to a sensor agent.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-1">
              <Label className="text-slate-300">Target Sensor</Label>
              <Select value={sensorId} onValueChange={setSensorId}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                  <SelectValue placeholder="Select sensor..." />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-600">
                  {sensors.filter(s => s.status === "online").map((s) => (
                    <SelectItem key={s.id} value={s.id} className="text-slate-200">
                      {s.hostname} ({s.platform})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1">
              <Label className="text-slate-300">Action</Label>
              <Select value={actionType} onValueChange={(v) => { setActionType(v); setParams({}); }}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-600">
                  {Object.entries(ACTION_CONFIGS).map(([key, c]) => (
                    <SelectItem key={key} value={key} className="text-slate-200">
                      <div className="flex items-center gap-2">
                        <span className={c.color}>{c.icon}</span>
                        <span>{c.label}</span>
                        {c.risk === "high" && (
                          <Badge variant="outline" className="text-xs border-red-500/30 text-red-400 px-1 py-0">High Risk</Badge>
                        )}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {cfg && (
                <p className="text-xs text-slate-500">{cfg.description}</p>
              )}
            </div>

            {cfg?.paramsSchema.map((field) => (
              <div key={field.key} className="space-y-1">
                <Label className="text-slate-300">{field.label}</Label>
                {field.type === "textarea" ? (
                  <Textarea
                    value={params[field.key] ?? ""}
                    onChange={(e) => setParams((p) => ({ ...p, [field.key]: e.target.value }))}
                    rows={4}
                    className="bg-slate-800 border-slate-600 text-slate-200 font-mono text-xs"
                  />
                ) : field.type === "select" && field.options ? (
                  <Select
                    value={params[field.key] ?? ""}
                    onValueChange={(v) => setParams((p) => ({ ...p, [field.key]: v }))}
                  >
                    <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                      <SelectValue placeholder={`Select ${field.label.toLowerCase()}...`} />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 border-slate-600">
                      {field.options.map((o) => (
                        <SelectItem key={o} value={o} className="text-slate-200 capitalize">{o}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    value={params[field.key] ?? ""}
                    onChange={(e) => setParams((p) => ({ ...p, [field.key]: e.target.value }))}
                    className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                  />
                )}
              </div>
            ))}

            {cfg?.risk === "high" && (
              <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-950/20 p-3">
                <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                <p className="text-xs text-amber-300">
                  This action requires admin approval before being dispatched to the sensor.
                </p>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="ghost" className="text-slate-400 hover:text-white" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              onClick={submit}
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
              Dispatch Action
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function AgentResponsePage() {
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const { toast } = useToast();

  const { data: sensorsData } = useQuery<{ data: NativeSensor[] }>({
    queryKey: ["/api/native/sensors"],
  });

  const { data: actionsData, isLoading } = useQuery<{ data: ResponseAction[] }>({
    queryKey: ["/api/native/response/actions", filterStatus, filterType],
    queryFn: () => {
      const p = new URLSearchParams();
      if (filterStatus !== "all") p.set("status", filterStatus);
      if (filterType !== "all") p.set("actionType", filterType);
      return apiRequest("GET", `/api/native/response/actions?${p}`).then((r) => r.json());
    },
  });

  const { data: statsData } = useQuery<{ data: ActionStats }>({
    queryKey: ["/api/native/response/stats"],
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/native/response/actions/${id}/approve`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      toast({ title: "Action approved and dispatched" });
    },
    onError: () => toast({ title: "Approval failed", variant: "destructive" }),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/native/response/actions/${id}/cancel`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
    },
  });

  const sensors = sensorsData?.data ?? [];
  const actions = actionsData?.data ?? [];
  const stats = statsData?.data;

  const pendingApproval = actions.filter((a) => a.requiresApproval && a.status === "pending");

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Zap className="h-6 w-6 text-amber-400" />
            Agent Response Actions
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Push kill, isolate, block, and quarantine commands directly to sensors. No CrowdStrike needed.
          </p>
        </div>
        <CreateActionDialog sensors={sensors} />
      </div>

      {/* USP banner */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            { icon: <StopCircle className="h-5 w-5 text-red-400" />, title: "Kill Process", desc: "Remote process termination by PID or name" },
            { icon: <WifiOff className="h-5 w-5 text-red-500" />, title: "Isolate Host", desc: "Network isolation via host firewall in <3 seconds" },
            { icon: <Network className="h-5 w-5 text-orange-400" />, title: "Block IP", desc: "Firewall rules pushed to iptables or Windows Firewall" },
            { icon: <HardDrive className="h-5 w-5 text-violet-400" />, title: "Forensics Collection", desc: "Grab memory/process/network snapshot before evidence is lost" },
          ].map((item) => (
            <div key={item.title} className="flex items-start gap-2">
              {item.icon}
              <div>
                <p className="text-xs font-medium text-white">{item.title}</p>
                <p className="text-xs text-slate-500">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Pending approval banner */}
      {pendingApproval.length > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-950/20 p-4">
          <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0" />
          <p className="text-sm text-amber-300 flex-1">
            <span className="font-semibold">{pendingApproval.length} action{pendingApproval.length > 1 ? "s" : ""}</span> pending approval.
          </p>
          <Button
            size="sm"
            className="bg-amber-700/50 hover:bg-amber-700 text-amber-200 text-xs"
            onClick={() => setFilterStatus("pending")}
          >
            Review
          </Button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Actions", value: actions.length, color: "text-white" },
          { label: "Completed", value: (stats?.byStatus?.completed ?? 0), color: "text-emerald-400" },
          { label: "Pending", value: (stats?.byStatus?.pending ?? 0) + (stats?.byStatus?.dispatched ?? 0), color: "text-yellow-400" },
          { label: "Failed", value: stats?.byStatus?.failed ?? 0, color: "text-red-400" },
        ].map((s) => (
          <Card key={s.label} className="bg-slate-900/60 border-slate-700/50">
            <CardContent className="p-4">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-xs text-slate-500 uppercase tracking-wider">{s.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-36 bg-slate-800 border-slate-600 text-slate-300">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-slate-800 border-slate-600">
            {["all", "pending", "dispatched", "completed", "failed", "cancelled"].map((s) => (
              <SelectItem key={s} value={s} className="text-slate-200 capitalize">{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="w-44 bg-slate-800 border-slate-600 text-slate-300">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-slate-800 border-slate-600">
            <SelectItem value="all" className="text-slate-200">All action types</SelectItem>
            {Object.entries(ACTION_CONFIGS).map(([k, c]) => (
              <SelectItem key={k} value={k} className="text-slate-200">{c.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="ghost"
          size="sm"
          className="text-slate-400 hover:text-white gap-1"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] })}
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Actions list */}
      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-lg" />)}</div>
      ) : actions.length === 0 ? (
        <div className="text-center py-12 text-slate-500">
          <Zap className="h-10 w-10 mx-auto mb-3 opacity-40" />
          <p>No response actions yet. Create one to push commands to your sensors.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {actions.map((a) => (
            <ActionRow
              key={a.id}
              action={a}
              onApprove={(id) => approveMutation.mutate(id)}
              onCancel={(id) => cancelMutation.mutate(id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
