import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Terminal,
  Shield,
  AlertTriangle,
  Search,
  CheckCircle,
  XCircle,
  Clock,
  Play,
  Ban,
  Crosshair,
  ShieldOff,
  FileWarning,
  Trash2,
  UserX,
  Globe,
  FileText,
  RefreshCw,
  Plus,
  Eye,
  Zap,
} from "lucide-react";
import { TablePageSkeleton } from "@/components/page-skeleton";

interface ResponseAction {
  id: string;
  sensorId: string;
  actionType: string;
  riskLevel: string;
  status: string;
  targetPid: number | null;
  targetProcessName: string | null;
  targetIp: string | null;
  targetFilePath: string | null;
  targetUserName: string | null;
  targetDomain: string | null;
  targetServiceName: string | null;
  scriptContent: string | null;
  scriptType: string | null;
  requestedBy: string | null;
  requestedByName: string | null;
  approvedBy: string | null;
  approvedByName: string | null;
  approvedAt: string | null;
  rejectedBy: string | null;
  rejectedReason: string | null;
  rejectedAt: string | null;
  completedAt: string | null;
  resultOutput: string | null;
  resultError: string | null;
  reason: string | null;
  createdAt: string;
}

interface ActionTypeRef {
  type: string;
  label: string;
  description: string;
  riskLevel: string;
  requiredFields: string[];
  icon: string;
}

interface ActionsResponse {
  actions: ResponseAction[];
  stats: {
    total: number;
    pendingCount: number;
    approvedCount: number;
    executingCount: number;
    completedCount: number;
    failedCount: number;
    rejectedCount: number;
    highRiskCount: number;
    mediumRiskCount: number;
    lowRiskCount: number;
  };
}

const statusColors: Record<string, string> = {
  pending_approval: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  approved: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  dispatched: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  executing: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  completed: "bg-green-500/20 text-green-400 border-green-500/30",
  failed: "bg-red-500/20 text-red-400 border-red-500/30",
  rejected: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  timed_out: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  cancelled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  simulated: "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

const riskColors: Record<string, string> = {
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
};

const actionIcons: Record<string, React.ReactNode> = {
  kill_process: <Crosshair className="h-4 w-4" />,
  isolate_host: <ShieldOff className="h-4 w-4" />,
  block_ip: <Ban className="h-4 w-4" />,
  quarantine_file: <FileWarning className="h-4 w-4" />,
  delete_file: <Trash2 className="h-4 w-4" />,
  disable_user: <UserX className="h-4 w-4" />,
  collect_forensics: <Search className="h-4 w-4" />,
  run_script: <Terminal className="h-4 w-4" />,
  block_domain: <Globe className="h-4 w-4" />,
  enable_logging: <FileText className="h-4 w-4" />,
  restart_service: <RefreshCw className="h-4 w-4" />,
};

const actionLabels: Record<string, string> = {
  kill_process: "Kill Process",
  isolate_host: "Isolate Host",
  block_ip: "Block IP",
  quarantine_file: "Quarantine File",
  delete_file: "Delete File",
  disable_user: "Disable User",
  collect_forensics: "Collect Forensics",
  run_script: "Run Script",
  block_domain: "Block Domain",
  enable_logging: "Enable Logging",
  restart_service: "Restart Service",
};

function getTargetDisplay(action: ResponseAction): string {
  if (action.targetProcessName) return action.targetProcessName;
  if (action.targetPid) return `PID ${action.targetPid}`;
  if (action.targetIp) return action.targetIp;
  if (action.targetFilePath) return action.targetFilePath;
  if (action.targetUserName) return action.targetUserName;
  if (action.targetDomain) return action.targetDomain;
  if (action.targetServiceName) return action.targetServiceName;
  return "—";
}

async function apiFetch(url: string, options?: RequestInit) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  // Include org context header
  try {
    const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
    if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
  } catch {
    /* SSR / privacy mode */
  }
  // Include CSRF token for mutating requests
  const method = options?.method?.toUpperCase() ?? "GET";
  if (method !== "GET" && method !== "HEAD") {
    const { fetchCsrfToken } = await import("@/lib/queryClient");
    const csrfToken = await fetchCsrfToken();
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(url, {
    ...options,
    headers: { ...headers, ...options?.headers },
    credentials: "include",
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const json = await res.json();
  // Unwrap the standard { data, meta, errors } envelope if present
  if (typeof json === "object" && json !== null && "data" in json && "meta" in json && "errors" in json)
    return json.data;
  return json;
}

export default function AgentResponsePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("pending");
  const [statusFilter, setStatusFilter] = useState("all");
  const [actionTypeFilter, setActionTypeFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedAction, setSelectedAction] = useState<ResponseAction | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [showRejectModal, setShowRejectModal] = useState<string | null>(null);

  // Form state for creating new action
  const [newAction, setNewAction] = useState({
    sensorId: "",
    actionType: "",
    targetPid: "",
    targetProcessName: "",
    targetIp: "",
    targetFilePath: "",
    targetUserName: "",
    targetDomain: "",
    targetServiceName: "",
    scriptContent: "",
    scriptType: "bash",
    reason: "",
  });

  const { data: actionsData, isLoading } = useQuery<ActionsResponse>({
    queryKey: ["/api/native/response/actions", statusFilter, actionTypeFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams();
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (actionTypeFilter !== "all") params.set("actionType", actionTypeFilter);
      if (searchQuery) params.set("q", searchQuery);
      return apiFetch(`/api/native/response/actions?${params}`);
    },
  });

  // Separate query for pending tab — not affected by All tab's filters
  const { data: pendingData } = useQuery<ActionsResponse>({
    queryKey: ["/api/native/response/actions", "pending_approval_tab"],
    queryFn: () => apiFetch("/api/native/response/actions?status=pending_approval"),
  });

  const { data: actionTypesData } = useQuery<{ actionTypes: ActionTypeRef[] }>({
    queryKey: ["/api/native/response/action-types"],
    queryFn: () => apiFetch("/api/native/response/action-types"),
  });

  const { data: sensorsData } = useQuery<{ sensors: { id: string; hostname: string }[] }>({
    queryKey: ["/api/native-sensors"],
    queryFn: () => apiFetch("/api/native-sensors?limit=100"),
  });

  const createAction = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/native/response/actions", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      setShowCreateModal(false);
      setNewAction({
        sensorId: "",
        actionType: "",
        targetPid: "",
        targetProcessName: "",
        targetIp: "",
        targetFilePath: "",
        targetUserName: "",
        targetDomain: "",
        targetServiceName: "",
        scriptContent: "",
        scriptType: "bash",
        reason: "",
      });
      toast({
        title: data.needsApproval ? "Action queued for approval" : "Action approved",
        description: data.message,
      });
    },
    onError: () => {
      toast({ title: "Failed to create action", variant: "destructive" });
    },
  });

  const approveAction = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/native/response/actions/${id}/approve`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      toast({ title: "Action approved" });
    },
    onError: () => {
      toast({ title: "Failed to approve", variant: "destructive" });
    },
  });

  const rejectAction = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiFetch(`/api/native/response/actions/${id}/reject`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      setShowRejectModal(null);
      setRejectReason("");
      toast({ title: "Action rejected" });
    },
  });

  const executeAction = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/native/response/actions/${id}/execute`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      toast({ title: "Action executed" });
    },
    onError: () => {
      toast({ title: "Failed to execute", variant: "destructive" });
    },
  });

  const cancelAction = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/native/response/actions/${id}/cancel`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response/actions"] });
      toast({ title: "Action cancelled" });
    },
  });

  const stats = actionsData?.stats;
  const pendingActions = pendingData?.actions || [];

  function handleSubmitAction() {
    const body: Record<string, unknown> = {
      sensorId: newAction.sensorId,
      actionType: newAction.actionType,
      reason: newAction.reason || undefined,
    };
    if (newAction.targetPid) body.targetPid = parseInt(newAction.targetPid);
    if (newAction.targetProcessName) body.targetProcessName = newAction.targetProcessName;
    if (newAction.targetIp) body.targetIp = newAction.targetIp;
    if (newAction.targetFilePath) body.targetFilePath = newAction.targetFilePath;
    if (newAction.targetUserName) body.targetUserName = newAction.targetUserName;
    if (newAction.targetDomain) body.targetDomain = newAction.targetDomain;
    if (newAction.targetServiceName) body.targetServiceName = newAction.targetServiceName;
    if (newAction.scriptContent) body.scriptContent = newAction.scriptContent;
    if (newAction.scriptType) body.scriptType = newAction.scriptType;
    createAction.mutate(body);
  }

  const selectedActionType = actionTypesData?.actionTypes?.find((t) => t.type === newAction.actionType);

  if (isLoading) return <TablePageSkeleton />;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Terminal className="h-6 w-6 text-teal-400" />
            Agent Remote Response
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Execute response actions on sensor agents with approval workflow
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)} className="bg-teal-600 hover:bg-teal-700">
          <Plus className="h-4 w-4 mr-1" />
          New Action
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Total Actions</div>
            <div className="text-2xl font-semibold mt-1">{stats?.total ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-yellow-500/20 border">
          <CardContent className="p-4">
            <div className="text-xs text-yellow-400">Pending Approval</div>
            <div className="text-2xl font-semibold mt-1 text-yellow-400">{stats?.pendingCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-green-400">Completed</div>
            <div className="text-2xl font-semibold mt-1 text-green-400">{stats?.completedCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-red-400">Failed</div>
            <div className="text-2xl font-semibold mt-1 text-red-400">{stats?.failedCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">High Risk</div>
            <div className="text-2xl font-semibold mt-1 text-red-400">{stats?.highRiskCount ?? 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="pending" className="gap-1.5">
            <Clock className="h-3.5 w-3.5" />
            Pending ({stats?.pendingCount ?? 0})
          </TabsTrigger>
          <TabsTrigger value="all" className="gap-1.5">
            <Zap className="h-3.5 w-3.5" />
            All Actions ({stats?.total ?? 0})
          </TabsTrigger>
        </TabsList>

        {/* PENDING APPROVAL TAB */}
        <TabsContent value="pending" className="mt-4 space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Action</TableHead>
                    <TableHead className="text-muted-foreground">Target</TableHead>
                    <TableHead className="text-muted-foreground">Risk</TableHead>
                    <TableHead className="text-muted-foreground">Requested By</TableHead>
                    <TableHead className="text-muted-foreground">Reason</TableHead>
                    <TableHead className="text-muted-foreground">Created</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : !pendingActions.length ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-12">
                        <div className="flex flex-col items-center gap-2">
                          <CheckCircle className="h-10 w-10 text-green-400/50" />
                          <p className="text-muted-foreground">No pending approvals</p>
                          <p className="text-xs text-muted-foreground">
                            High and medium risk actions require admin approval
                          </p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    pendingActions.map((action) => (
                      <TableRow key={action.id} className="border-zinc-800">
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {actionIcons[action.actionType]}
                            <span className="font-medium">{actionLabels[action.actionType] || action.actionType}</span>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-sm">{getTargetDisplay(action)}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={riskColors[action.riskLevel] || ""}>
                            {action.riskLevel}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">{action.requestedByName || "—"}</TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                          {action.reason || "—"}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(action.createdAt).toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex gap-1 justify-end">
                            <Button
                              size="sm"
                              className="h-7 text-xs bg-green-600 hover:bg-green-700"
                              onClick={() => approveAction.mutate(action.id)}
                            >
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-xs border-red-500/30 text-red-400 hover:bg-red-500/10"
                              onClick={() => setShowRejectModal(action.id)}
                            >
                              <XCircle className="h-3 w-3 mr-1" />
                              Reject
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ALL ACTIONS TAB */}
        <TabsContent value="all" className="mt-4 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search target..."
                className="pl-9 bg-zinc-900/50 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="pending_approval">Pending</SelectItem>
                <SelectItem value="approved">Approved</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="rejected">Rejected</SelectItem>
              </SelectContent>
            </Select>
            <Select value={actionTypeFilter} onValueChange={setActionTypeFilter}>
              <SelectTrigger className="w-[160px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Action Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {Object.entries(actionLabels).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Action</TableHead>
                    <TableHead className="text-muted-foreground">Target</TableHead>
                    <TableHead className="text-muted-foreground">Risk</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                    <TableHead className="text-muted-foreground">Requested</TableHead>
                    <TableHead className="text-muted-foreground">Created</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : !actionsData?.actions?.length ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-12">
                        <div className="flex flex-col items-center gap-2">
                          <Terminal className="h-10 w-10 text-muted-foreground/50" />
                          <p className="text-muted-foreground">No response actions</p>
                          <p className="text-xs text-muted-foreground">
                            Create an action to dispatch commands to sensor agents
                          </p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    actionsData.actions.map((action) => (
                      <TableRow
                        key={action.id}
                        className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                        onClick={() => setSelectedAction(action)}
                      >
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {actionIcons[action.actionType]}
                            <span className="font-medium">{actionLabels[action.actionType] || action.actionType}</span>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-sm max-w-xs truncate">
                          {getTargetDisplay(action)}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={riskColors[action.riskLevel] || ""}>
                            {action.riskLevel}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <Badge variant="outline" className={statusColors[action.status] || ""}>
                              {action.status.replace(/_/g, " ")}
                            </Badge>
                            {action.status === "simulated" && (
                              <span
                                className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                title="No sensor agent deployed — action was simulated"
                              >
                                No Sensor
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-sm">{action.requestedByName || "—"}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(action.createdAt).toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex gap-1 justify-end" onClick={(e) => e.stopPropagation()}>
                            {action.status === "pending_approval" && (
                              <>
                                <Button
                                  size="sm"
                                  className="h-7 text-xs bg-green-600 hover:bg-green-700"
                                  onClick={() => approveAction.mutate(action.id)}
                                >
                                  Approve
                                </Button>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="h-7 text-xs border-red-500/30 text-red-400"
                                  onClick={() => setShowRejectModal(action.id)}
                                >
                                  Reject
                                </Button>
                              </>
                            )}
                            {action.status === "approved" && (
                              <Button
                                size="sm"
                                className="h-7 text-xs bg-blue-600 hover:bg-blue-700"
                                onClick={() => executeAction.mutate(action.id)}
                              >
                                <Play className="h-3 w-3 mr-1" />
                                Execute
                              </Button>
                            )}
                            {["pending_approval", "approved"].includes(action.status) && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs"
                                onClick={() => cancelAction.mutate(action.id)}
                              >
                                Cancel
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Action Modal */}
      <Dialog open={showCreateModal} onOpenChange={setShowCreateModal}>
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="h-5 w-5 text-teal-400" />
              New Response Action
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Target Sensor</Label>
              <Select value={newAction.sensorId} onValueChange={(v) => setNewAction({ ...newAction, sensorId: v })}>
                <SelectTrigger className="bg-zinc-900/50 border-zinc-800">
                  <SelectValue placeholder="Select sensor..." />
                </SelectTrigger>
                <SelectContent>
                  {sensorsData?.sensors?.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.hostname}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Action Type</Label>
              <Select value={newAction.actionType} onValueChange={(v) => setNewAction({ ...newAction, actionType: v })}>
                <SelectTrigger className="bg-zinc-900/50 border-zinc-800">
                  <SelectValue placeholder="Select action..." />
                </SelectTrigger>
                <SelectContent>
                  {actionTypesData?.actionTypes?.map((t) => (
                    <SelectItem key={t.type} value={t.type}>
                      <span className="flex items-center gap-2">
                        {actionIcons[t.type]}
                        {t.label}
                        <Badge variant="outline" className={`ml-1 text-[10px] ${riskColors[t.riskLevel] || ""}`}>
                          {t.riskLevel}
                        </Badge>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selectedActionType && <p className="text-xs text-muted-foreground">{selectedActionType.description}</p>}
            </div>

            {/* Conditional fields based on action type */}
            {["kill_process"].includes(newAction.actionType) && (
              <>
                <div className="space-y-2">
                  <Label>Process Name</Label>
                  <Input
                    className="bg-zinc-900/50 border-zinc-800"
                    placeholder="e.g. malware.exe"
                    value={newAction.targetProcessName}
                    onChange={(e) => setNewAction({ ...newAction, targetProcessName: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>PID (optional)</Label>
                  <Input
                    className="bg-zinc-900/50 border-zinc-800"
                    placeholder="e.g. 12345"
                    type="number"
                    value={newAction.targetPid}
                    onChange={(e) => setNewAction({ ...newAction, targetPid: e.target.value })}
                  />
                </div>
              </>
            )}

            {["block_ip"].includes(newAction.actionType) && (
              <div className="space-y-2">
                <Label>IP Address</Label>
                <Input
                  className="bg-zinc-900/50 border-zinc-800"
                  placeholder="e.g. 192.168.1.100"
                  value={newAction.targetIp}
                  onChange={(e) => setNewAction({ ...newAction, targetIp: e.target.value })}
                />
              </div>
            )}

            {["quarantine_file", "delete_file"].includes(newAction.actionType) && (
              <div className="space-y-2">
                <Label>File Path</Label>
                <Input
                  className="bg-zinc-900/50 border-zinc-800"
                  placeholder="e.g. /tmp/suspicious.bin"
                  value={newAction.targetFilePath}
                  onChange={(e) => setNewAction({ ...newAction, targetFilePath: e.target.value })}
                />
              </div>
            )}

            {["disable_user"].includes(newAction.actionType) && (
              <div className="space-y-2">
                <Label>Username</Label>
                <Input
                  className="bg-zinc-900/50 border-zinc-800"
                  placeholder="e.g. john.doe"
                  value={newAction.targetUserName}
                  onChange={(e) => setNewAction({ ...newAction, targetUserName: e.target.value })}
                />
              </div>
            )}

            {["block_domain"].includes(newAction.actionType) && (
              <div className="space-y-2">
                <Label>Domain</Label>
                <Input
                  className="bg-zinc-900/50 border-zinc-800"
                  placeholder="e.g. malicious-site.com"
                  value={newAction.targetDomain}
                  onChange={(e) => setNewAction({ ...newAction, targetDomain: e.target.value })}
                />
              </div>
            )}

            {["restart_service"].includes(newAction.actionType) && (
              <div className="space-y-2">
                <Label>Service Name</Label>
                <Input
                  className="bg-zinc-900/50 border-zinc-800"
                  placeholder="e.g. nginx"
                  value={newAction.targetServiceName}
                  onChange={(e) => setNewAction({ ...newAction, targetServiceName: e.target.value })}
                />
              </div>
            )}

            {["run_script"].includes(newAction.actionType) && (
              <>
                <div className="space-y-2">
                  <Label>Script Type</Label>
                  <Select
                    value={newAction.scriptType}
                    onValueChange={(v) => setNewAction({ ...newAction, scriptType: v })}
                  >
                    <SelectTrigger className="bg-zinc-900/50 border-zinc-800">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="bash">Bash</SelectItem>
                      <SelectItem value="powershell">PowerShell</SelectItem>
                      <SelectItem value="python">Python</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Script Content</Label>
                  <Textarea
                    className="bg-zinc-900/50 border-zinc-800 font-mono text-sm min-h-[120px]"
                    placeholder="#!/bin/bash&#10;# Your script here"
                    value={newAction.scriptContent}
                    onChange={(e) => setNewAction({ ...newAction, scriptContent: e.target.value })}
                  />
                </div>
              </>
            )}

            <div className="space-y-2">
              <Label>Reason / Justification</Label>
              <Textarea
                className="bg-zinc-900/50 border-zinc-800"
                placeholder="Why is this action needed?"
                value={newAction.reason}
                onChange={(e) => setNewAction({ ...newAction, reason: e.target.value })}
              />
            </div>

            {selectedActionType && (
              <div className="flex items-center gap-2 p-3 rounded-lg border border-zinc-800 bg-zinc-900/50">
                <AlertTriangle
                  className={`h-4 w-4 ${
                    selectedActionType.riskLevel === "high"
                      ? "text-red-400"
                      : selectedActionType.riskLevel === "medium"
                        ? "text-yellow-400"
                        : "text-green-400"
                  }`}
                />
                <span className="text-sm text-muted-foreground">
                  {selectedActionType.riskLevel === "high" || selectedActionType.riskLevel === "medium"
                    ? "This action requires admin approval before execution"
                    : "This action will be auto-approved (low risk)"}
                </span>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSubmitAction}
              disabled={!newAction.sensorId || !newAction.actionType || createAction.isPending}
              className="bg-teal-600 hover:bg-teal-700"
            >
              {createAction.isPending ? "Creating..." : "Create Action"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Action Detail Dialog */}
      <Dialog open={!!selectedAction} onOpenChange={() => setSelectedAction(null)}>
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedAction && actionIcons[selectedAction.actionType]}
              {selectedAction && (actionLabels[selectedAction.actionType] || selectedAction.actionType)}
            </DialogTitle>
          </DialogHeader>
          {selectedAction && (
            <div className="space-y-4">
              <div className="flex gap-2 flex-wrap">
                <Badge variant="outline" className={statusColors[selectedAction.status] || ""}>
                  {selectedAction.status.replace(/_/g, " ")}
                </Badge>
                {selectedAction.status === "simulated" && (
                  <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/20">
                    No Sensor Deployed
                  </Badge>
                )}
                <Badge variant="outline" className={riskColors[selectedAction.riskLevel] || ""}>
                  {selectedAction.riskLevel} risk
                </Badge>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Target</span>
                  <span className="font-mono">{getTargetDisplay(selectedAction)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Requested By</span>
                  <span>{selectedAction.requestedByName || "—"}</span>
                </div>
                {selectedAction.approvedByName && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Approved By</span>
                    <span>{selectedAction.approvedByName}</span>
                  </div>
                )}
                {selectedAction.reason && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Reason</span>
                    <span className="max-w-xs text-right">{selectedAction.reason}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Created</span>
                  <span>{new Date(selectedAction.createdAt).toLocaleString()}</span>
                </div>
                {selectedAction.completedAt && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Completed</span>
                    <span>{new Date(selectedAction.completedAt).toLocaleString()}</span>
                  </div>
                )}
              </div>

              {selectedAction.resultOutput && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Result</p>
                  <pre className="text-sm bg-zinc-900 rounded p-3 border border-zinc-800 whitespace-pre-wrap font-mono">
                    {selectedAction.resultOutput}
                  </pre>
                </div>
              )}

              {selectedAction.resultError && (
                <div>
                  <p className="text-xs text-red-400 mb-1">Error</p>
                  <pre className="text-sm bg-red-950/30 rounded p-3 border border-red-500/30 whitespace-pre-wrap font-mono text-red-400">
                    {selectedAction.resultError}
                  </pre>
                </div>
              )}

              {selectedAction.rejectedReason && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Rejection Reason</p>
                  <p className="text-sm bg-zinc-900 rounded p-3 border border-zinc-800">
                    {selectedAction.rejectedReason}
                  </p>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Reject Reason Modal */}
      <Dialog open={!!showRejectModal} onOpenChange={() => setShowRejectModal(null)}>
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-sm">
          <DialogHeader>
            <DialogTitle>Reject Action</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <Label>Reason for rejection</Label>
            <Textarea
              className="bg-zinc-900/50 border-zinc-800"
              placeholder="Why is this action being rejected?"
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRejectModal(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (showRejectModal) {
                  rejectAction.mutate({ id: showRejectModal, reason: rejectReason });
                }
              }}
            >
              Reject
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
