import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Smartphone,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  WifiOff,
  Lock,
  Unlock,
  Eye,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Monitor,
  Globe,
  Clock,
  Activity,
  Laptop,
  Server,
  Users,
  TrendingUp,
} from "lucide-react";

const API_BASE = "/api/mobile";

async function apiRequest(url: string, options?: RequestInit) {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (csrfMeta) {
    headers["x-csrf-token"] = csrfMeta.getAttribute("content") || "";
  }
  const resp = await fetch(url, { ...options, headers, credentials: "include" });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ message: resp.statusText }));
    throw new Error(body.message || resp.statusText);
  }
  return resp.json();
}

function riskBadge(level: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-green-600 text-white",
  };
  return <Badge className={colors[level] || "bg-muted"}>{level}</Badge>;
}

function complianceBadge(status: string) {
  const map: Record<string, { color: string; icon: React.ReactNode }> = {
    compliant: { color: "bg-green-600 text-white", icon: <CheckCircle2 className="h-3 w-3" /> },
    "non-compliant": { color: "bg-red-600 text-white", icon: <XCircle className="h-3 w-3" /> },
    pending: { color: "bg-yellow-500 text-black", icon: <Clock className="h-3 w-3" /> },
    unknown: { color: "bg-muted", icon: <Eye className="h-3 w-3" /> },
  };
  const entry = map[status] || map.unknown;
  return (
    <Badge className={`${entry.color} gap-1`}>
      {entry.icon}
      {status}
    </Badge>
  );
}

function platformIcon(platform: string) {
  switch (platform) {
    case "ios":
    case "android":
      return <Smartphone className="h-4 w-4" />;
    case "macos":
    case "windows":
    case "linux":
      return <Laptop className="h-4 w-4" />;
    default:
      return <Monitor className="h-4 w-4" />;
  }
}

// ─── Dashboard Tab ───────────────────────────────────────────────────────────

function DashboardTab() {
  const { data: dashboard } = useQuery({
    queryKey: ["mobile-dashboard"],
    queryFn: () => apiRequest(`${API_BASE}/dashboard`),
  });

  if (!dashboard) {
    return <div className="text-muted-foreground p-4">Loading dashboard...</div>;
  }

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Devices</CardDescription>
            <CardTitle className="text-3xl">{dashboard.totalDevices}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Smartphone className="h-4 w-4" />
              Managed fleet
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Compliance Rate</CardDescription>
            <CardTitle className="text-3xl">{dashboard.complianceRate}%</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <ShieldCheck className="h-4 w-4" />
              Fleet compliance
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active Threats</CardDescription>
            <CardTitle className="text-3xl text-red-500">{dashboard.activeThreats}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <AlertTriangle className="h-4 w-4" />
              Unresolved threats
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active Sessions</CardDescription>
            <CardTitle className="text-3xl">{dashboard.activeSessions}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Users className="h-4 w-4" />
              Remote workers online
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk indicators */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-red-500/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              Rooted/Jailbroken
            </CardTitle>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold text-red-500">{dashboard.rootedDevices}</span>
            <span className="text-sm text-muted-foreground ml-2">devices</span>
          </CardContent>
        </Card>

        <Card className="border-orange-500/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Unlock className="h-4 w-4 text-orange-500" />
              Unencrypted
            </CardTitle>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold text-orange-500">{dashboard.unencryptedDevices}</span>
            <span className="text-sm text-muted-foreground ml-2">devices</span>
          </CardContent>
        </Card>

        <Card className="border-yellow-500/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Monitor className="h-4 w-4 text-yellow-500" />
              No MDM
            </CardTitle>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold text-yellow-500">{dashboard.noMdmDevices}</span>
            <span className="text-sm text-muted-foreground ml-2">devices</span>
          </CardContent>
        </Card>
      </div>

      {/* Platform & Risk breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">By Platform</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(dashboard.byPlatform || []).map((p: { platform: string; count: number }) => (
                <div key={p.platform} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {platformIcon(p.platform)}
                    <span className="capitalize">{p.platform}</span>
                  </div>
                  <Badge variant="secondary">{Number(p.count)}</Badge>
                </div>
              ))}
              {(!dashboard.byPlatform || dashboard.byPlatform.length === 0) && (
                <p className="text-sm text-muted-foreground">No devices registered</p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">By Risk Level</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(dashboard.byRisk || []).map((r: { riskLevel: string; count: number }) => (
                <div key={r.riskLevel} className="flex items-center justify-between">
                  {riskBadge(r.riskLevel)}
                  <Badge variant="secondary">{Number(r.count)}</Badge>
                </div>
              ))}
              {(!dashboard.byRisk || dashboard.byRisk.length === 0) && (
                <p className="text-sm text-muted-foreground">No risk data</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Threats */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Recent Threats</CardTitle>
        </CardHeader>
        <CardContent>
          {dashboard.recentThreats && dashboard.recentThreats.length > 0 ? (
            <div className="space-y-2">
              {dashboard.recentThreats.map((t: Record<string, unknown>) => (
                <div key={t.id as string} className="flex items-center justify-between border-b border-border/50 pb-2">
                  <div>
                    <p className="text-sm font-medium">{t.title as string}</p>
                    <p className="text-xs text-muted-foreground">{t.threatType as string}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {riskBadge(t.severity as string)}
                    <Badge variant="outline">{t.status as string}</Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No threats detected</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Devices Tab ─────────────────────────────────────────────────────────────

function DevicesTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [platformFilter, setPlatformFilter] = useState("all");
  const [complianceFilter, setComplianceFilter] = useState("all");
  const [showAddDialog, setShowAddDialog] = useState(false);

  const { data: devices = [] } = useQuery({
    queryKey: ["mobile-devices", platformFilter, complianceFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (platformFilter !== "all") params.set("platform", platformFilter);
      if (complianceFilter !== "all") params.set("compliance", complianceFilter);
      return apiRequest(`${API_BASE}/devices?${params}`);
    },
  });

  const createDevice = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest(`${API_BASE}/devices`, { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mobile-devices"] });
      queryClient.invalidateQueries({ queryKey: ["mobile-dashboard"] });
      toast({ title: "Device registered" });
      setShowAddDialog(false);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const postureCheck = useMutation({
    mutationFn: (id: string) => apiRequest(`${API_BASE}/devices/${id}/posture-check`, { method: "POST" }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["mobile-devices"] });
      toast({ title: "Posture check complete", description: `${data.checksPassed}/${data.checksRun} passed` });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deleteDevice = useMutation({
    mutationFn: (id: string) => apiRequest(`${API_BASE}/devices/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mobile-devices"] });
      queryClient.invalidateQueries({ queryKey: ["mobile-dashboard"] });
      toast({ title: "Device deleted" });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const handleAdd = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    createDevice.mutate({
      deviceName: fd.get("deviceName"),
      platform: fd.get("platform"),
      osVersion: fd.get("osVersion") || undefined,
      model: fd.get("model") || undefined,
      serialNumber: fd.get("serialNumber") || undefined,
      isEncrypted: fd.get("isEncrypted") === "on",
      hasScreenLock: fd.get("hasScreenLock") === "on",
      hasFirewall: fd.get("hasFirewall") === "on",
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Select value={platformFilter} onValueChange={setPlatformFilter}>
            <SelectTrigger className="w-36">
              <SelectValue placeholder="Platform" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Platforms</SelectItem>
              <SelectItem value="ios">iOS</SelectItem>
              <SelectItem value="android">Android</SelectItem>
              <SelectItem value="macos">macOS</SelectItem>
              <SelectItem value="windows">Windows</SelectItem>
              <SelectItem value="linux">Linux</SelectItem>
            </SelectContent>
          </Select>

          <Select value={complianceFilter} onValueChange={setComplianceFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Compliance" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="compliant">Compliant</SelectItem>
              <SelectItem value="non-compliant">Non-Compliant</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="unknown">Unknown</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> Register Device
            </Button>
          </DialogTrigger>
          <DialogContent>
            <form onSubmit={handleAdd}>
              <DialogHeader>
                <DialogTitle>Register Mobile Device</DialogTitle>
                <DialogDescription>Add a new device to the fleet</DialogDescription>
              </DialogHeader>
              <div className="grid gap-3 py-4">
                <div>
                  <Label htmlFor="deviceName">Device Name *</Label>
                  <Input id="deviceName" name="deviceName" required />
                </div>
                <div>
                  <Label htmlFor="platform">Platform *</Label>
                  <select
                    name="platform"
                    id="platform"
                    required
                    className="w-full border rounded px-3 py-2 bg-background text-foreground"
                  >
                    <option value="ios">iOS</option>
                    <option value="android">Android</option>
                    <option value="macos">macOS</option>
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                    <option value="chromeos">Chrome OS</option>
                  </select>
                </div>
                <div>
                  <Label htmlFor="osVersion">OS Version</Label>
                  <Input id="osVersion" name="osVersion" placeholder="e.g. 17.4.1" />
                </div>
                <div>
                  <Label htmlFor="model">Model</Label>
                  <Input id="model" name="model" placeholder="e.g. iPhone 15 Pro" />
                </div>
                <div>
                  <Label htmlFor="serialNumber">Serial Number</Label>
                  <Input id="serialNumber" name="serialNumber" />
                </div>
                <div className="flex items-center gap-6">
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="isEncrypted" /> Encrypted
                  </label>
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="hasScreenLock" /> Screen Lock
                  </label>
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="hasFirewall" /> Firewall
                  </label>
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createDevice.isPending}>
                  {createDevice.isPending ? "Registering..." : "Register"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Device list */}
      <div className="space-y-2">
        {devices.length === 0 && (
          <Card>
            <CardContent className="p-6 text-center text-muted-foreground">
              No devices found. Register a device or sync from your MDM provider.
            </CardContent>
          </Card>
        )}

        {devices.map((device: Record<string, unknown>) => (
          <Card key={device.id as string}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {platformIcon(device.platform as string)}
                  <div>
                    <p className="font-medium">{device.deviceName as string}</p>
                    <p className="text-xs text-muted-foreground">
                      {(device.platform as string).toUpperCase()} {device.osVersion as string}
                      {device.model ? ` \u2022 ${device.model}` : ""}
                      {device.serialNumber ? ` \u2022 S/N: ${device.serialNumber}` : ""}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {complianceBadge(device.complianceStatus as string)}
                  {riskBadge(device.riskLevel as string)}

                  <div className="flex items-center gap-1 text-xs text-muted-foreground ml-2">
                    {device.isEncrypted ? (
                      <Lock className="h-3 w-3 text-green-500" />
                    ) : (
                      <Unlock className="h-3 w-3 text-red-500" />
                    )}
                    {device.isVpnActive ? (
                      <Wifi className="h-3 w-3 text-green-500" />
                    ) : (
                      <WifiOff className="h-3 w-3 text-muted-foreground" />
                    )}
                    {device.hasMdm ? (
                      <ShieldCheck className="h-3 w-3 text-green-500" />
                    ) : (
                      <ShieldAlert className="h-3 w-3 text-yellow-500" />
                    )}
                  </div>

                  <Button size="sm" variant="outline" onClick={() => postureCheck.mutate(device.id as string)}>
                    <RefreshCw className="h-3 w-3 mr-1" /> Check
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => {
                      if (confirm("Delete this device?")) deleteDevice.mutate(device.id as string);
                    }}
                  >
                    <XCircle className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── Threats Tab ─────────────────────────────────────────────────────────────

function ThreatsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("all");

  const { data: threats = [] } = useQuery({
    queryKey: ["mobile-threats", statusFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (statusFilter !== "all") params.set("status", statusFilter);
      return apiRequest(`${API_BASE}/threats?${params}`);
    },
  });

  const resolveThreats = useMutation({
    mutationFn: (id: string) =>
      apiRequest(`${API_BASE}/threats/${id}`, { method: "PATCH", body: JSON.stringify({ status: "resolved" }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mobile-threats"] });
      queryClient.invalidateQueries({ queryKey: ["mobile-dashboard"] });
      toast({ title: "Threat resolved" });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="investigating">Investigating</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {threats.length === 0 && (
        <Card>
          <CardContent className="p-6 text-center text-muted-foreground">No threats detected</CardContent>
        </Card>
      )}

      {threats.map((threat: Record<string, unknown>) => (
        <Card key={threat.id as string}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <p className="font-medium">{threat.title as string}</p>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Type: {threat.threatType as string}
                  {threat.appName ? ` \u2022 App: ${threat.appName}` : ""}
                  {threat.networkSsid ? ` \u2022 Network: ${threat.networkSsid}` : ""}
                </p>
                {threat.description ? (
                  <p className="text-sm text-muted-foreground mt-1">{String(threat.description)}</p>
                ) : null}
              </div>

              <div className="flex items-center gap-2">
                {riskBadge(threat.severity as string)}
                <Badge variant="outline">{threat.status as string}</Badge>
                {threat.status !== "resolved" && (
                  <Button size="sm" variant="outline" onClick={() => resolveThreats.mutate(threat.id as string)}>
                    Resolve
                  </Button>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── ZTNA Policies Tab ───────────────────────────────────────────────────────

function ZtnaTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAddDialog, setShowAddDialog] = useState(false);

  const { data: policies = [] } = useQuery({
    queryKey: ["ztna-policies"],
    queryFn: () => apiRequest(`${API_BASE}/ztna/policies`),
  });

  const createPolicy = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest(`${API_BASE}/ztna/policies`, { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ztna-policies"] });
      toast({ title: "ZTNA policy created" });
      setShowAddDialog(false);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const togglePolicy = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiRequest(`${API_BASE}/ztna/policies/${id}`, { method: "PUT", body: JSON.stringify({ enabled }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ztna-policies"] });
      toast({ title: "Policy updated" });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deletePolicy = useMutation({
    mutationFn: (id: string) => apiRequest(`${API_BASE}/ztna/policies/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ztna-policies"] });
      toast({ title: "Policy deleted" });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const handleAdd = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    createPolicy.mutate({
      name: fd.get("name"),
      description: fd.get("description") || undefined,
      action: fd.get("action"),
      priority: parseInt(fd.get("priority") as string, 10) || 100,
      requireEncryption: fd.get("requireEncryption") === "on",
      requireMdm: fd.get("requireMdm") === "on",
      requireScreenLock: fd.get("requireScreenLock") === "on",
      blockRooted: fd.get("blockRooted") === "on",
      requireMfa: fd.get("requireMfa") === "on",
      maxRiskScore: parseInt(fd.get("maxRiskScore") as string, 10) || 70,
      conditions: { type: "device-posture" },
    });
  };

  const actionColors: Record<string, string> = {
    allow: "bg-green-600 text-white",
    deny: "bg-red-600 text-white",
    "step-up-mfa": "bg-blue-600 text-white",
    quarantine: "bg-orange-500 text-white",
    monitor: "bg-yellow-500 text-black",
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Zero Trust Network Access policies evaluate device posture before granting access
        </p>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> Add Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <form onSubmit={handleAdd}>
              <DialogHeader>
                <DialogTitle>Create ZTNA Policy</DialogTitle>
                <DialogDescription>Define access conditions and enforcement action</DialogDescription>
              </DialogHeader>
              <div className="grid gap-3 py-4">
                <div>
                  <Label htmlFor="name">Policy Name *</Label>
                  <Input id="name" name="name" required />
                </div>
                <div>
                  <Label htmlFor="description">Description</Label>
                  <Textarea id="description" name="description" rows={2} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label htmlFor="action">Action</Label>
                    <select
                      name="action"
                      id="action"
                      className="w-full border rounded px-3 py-2 bg-background text-foreground"
                    >
                      <option value="deny">Deny</option>
                      <option value="allow">Allow</option>
                      <option value="step-up-mfa">Step-up MFA</option>
                      <option value="quarantine">Quarantine</option>
                      <option value="monitor">Monitor</option>
                    </select>
                  </div>
                  <div>
                    <Label htmlFor="priority">Priority</Label>
                    <Input id="priority" name="priority" type="number" defaultValue={100} />
                  </div>
                </div>
                <div>
                  <Label htmlFor="maxRiskScore">Max Risk Score (0-100)</Label>
                  <Input id="maxRiskScore" name="maxRiskScore" type="number" defaultValue={70} />
                </div>
                <div className="space-y-2">
                  <p className="text-sm font-medium">Posture Requirements</p>
                  <div className="flex flex-wrap gap-4">
                    <label className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="requireEncryption" defaultChecked /> Require Encryption
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="requireMdm" defaultChecked /> Require MDM
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="requireScreenLock" defaultChecked /> Require Screen Lock
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="blockRooted" defaultChecked /> Block Rooted
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="requireMfa" /> Require MFA
                    </label>
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createPolicy.isPending}>
                  {createPolicy.isPending ? "Creating..." : "Create Policy"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {policies.length === 0 && (
        <Card>
          <CardContent className="p-6 text-center text-muted-foreground">
            No ZTNA policies configured. Create a policy to enforce device posture checks.
          </CardContent>
        </Card>
      )}

      {policies.map((policy: Record<string, unknown>) => (
        <Card key={policy.id as string}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Shield className="h-5 w-5 text-blue-500" />
                <div>
                  <p className="font-medium">{policy.name as string}</p>
                  <p className="text-xs text-muted-foreground">
                    Priority: {policy.priority as number}
                    {policy.description ? ` \u2022 ${policy.description}` : ""}
                  </p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {policy.requireEncryption ? (
                      <Badge variant="outline" className="text-xs">
                        Encryption
                      </Badge>
                    ) : null}
                    {policy.requireMdm ? (
                      <Badge variant="outline" className="text-xs">
                        MDM
                      </Badge>
                    ) : null}
                    {policy.requireScreenLock ? (
                      <Badge variant="outline" className="text-xs">
                        Screen Lock
                      </Badge>
                    ) : null}
                    {policy.blockRooted ? (
                      <Badge variant="outline" className="text-xs">
                        No Root
                      </Badge>
                    ) : null}
                    {policy.requireMfa ? (
                      <Badge variant="outline" className="text-xs">
                        MFA
                      </Badge>
                    ) : null}
                    {policy.maxRiskScore ? (
                      <Badge variant="outline" className="text-xs">
                        Max Risk: {policy.maxRiskScore as number}
                      </Badge>
                    ) : null}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Badge className={actionColors[policy.action as string] || "bg-muted"}>{policy.action as string}</Badge>
                <Switch
                  checked={policy.enabled as boolean}
                  onCheckedChange={(enabled) => togglePolicy.mutate({ id: policy.id as string, enabled })}
                />
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => {
                    if (confirm("Delete this policy?")) deletePolicy.mutate(policy.id as string);
                  }}
                >
                  <XCircle className="h-3 w-3" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Sessions Tab ────────────────────────────────────────────────────────────

function SessionsTab() {
  const [activeOnly, setActiveOnly] = useState(true);

  const { data: sessions = [] } = useQuery({
    queryKey: ["remote-sessions", activeOnly],
    queryFn: () => {
      const params = new URLSearchParams();
      if (activeOnly) params.set("active", "true");
      return apiRequest(`${API_BASE}/sessions?${params}`);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={activeOnly} onCheckedChange={setActiveOnly} />
          Active sessions only
        </label>
      </div>

      {sessions.length === 0 && (
        <Card>
          <CardContent className="p-6 text-center text-muted-foreground">
            No {activeOnly ? "active " : ""}remote worker sessions found
          </CardContent>
        </Card>
      )}

      {sessions.map((session: Record<string, unknown>) => {
        const riskScore = session.riskScore as number;
        const riskColor =
          riskScore >= 75
            ? "text-red-500"
            : riskScore >= 50
              ? "text-orange-500"
              : riskScore >= 25
                ? "text-yellow-500"
                : "text-green-500";
        const factors = (session.riskFactors || []) as string[];

        return (
          <Card key={session.id as string}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Globe className="h-5 w-5 text-blue-500" />
                  <div>
                    <p className="font-medium">User: {session.userId as string}</p>
                    <p className="text-xs text-muted-foreground">
                      {String(session.country || "Unknown")}
                      {session.city ? `, ${String(session.city)}` : ""}
                      {" \u2022 "}
                      {String(session.ipAddress || "No IP")}
                      {session.vpnConnected ? " \u2022 VPN" : " \u2022 No VPN"}
                    </p>
                    {factors.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {factors.map((f, i) => (
                          <Badge key={i} variant="outline" className="text-xs text-orange-500">
                            {f}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <p className={`text-lg font-bold ${riskColor}`}>{riskScore}</p>
                    <p className="text-xs text-muted-foreground">risk score</p>
                  </div>
                  {!session.sessionEnd ? (
                    <Badge className="bg-green-600 text-white">Active</Badge>
                  ) : (
                    <Badge variant="secondary">Ended</Badge>
                  )}
                  {session.isOffHours ? (
                    <Badge variant="outline" className="text-orange-500">
                      <Clock className="h-3 w-3 mr-1" /> Off-hours
                    </Badge>
                  ) : null}
                  {session.isNewLocation ? (
                    <Badge variant="outline" className="text-red-500">
                      <Globe className="h-3 w-3 mr-1" /> New Location
                    </Badge>
                  ) : null}
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ─── MDM Tab ─────────────────────────────────────────────────────────────────

function MdmTab() {
  const { data: providers = [] } = useQuery({
    queryKey: ["mdm-status"],
    queryFn: () => apiRequest(`${API_BASE}/mdm/status`),
  });

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Connect your MDM solution to automatically sync device inventory and compliance data
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {providers.map((provider: Record<string, unknown>) => (
          <Card key={provider.provider as string} className={provider.configured ? "border-green-500/30" : ""}>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Server className="h-4 w-4" />
                {provider.label as string}
              </CardTitle>
              <CardDescription>{provider.description as string}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Status</span>
                  {provider.configured ? (
                    <Badge className="bg-green-600 text-white">Connected</Badge>
                  ) : (
                    <Badge variant="secondary">Not Connected</Badge>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Devices</span>
                  <span className="font-medium">{provider.deviceCount as number}</span>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(provider.supportedPlatforms as string[]).map((p) => (
                    <Badge key={p} variant="outline" className="text-xs capitalize">
                      {p}
                    </Badge>
                  ))}
                </div>
                <Button variant="outline" size="sm" className="w-full mt-2" disabled={!provider.configured && true}>
                  {provider.configured ? "Sync Now" : "Configure"}
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Integration guides */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Integration Guides</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="border rounded p-3">
              <p className="font-medium text-sm">Jamf Pro Setup</p>
              <p className="text-xs text-muted-foreground mt-1">
                1. In Jamf Pro, go to Settings &gt; API Roles and Clients
                <br />
                2. Create a new API client with &quot;Read Mobile Devices&quot; and &quot;Read Computers&quot;
                permissions
                <br />
                3. Copy the Client ID and Client Secret
                <br />
                4. Enter your Jamf Pro URL (e.g. https://yourcompany.jamfcloud.com)
              </p>
            </div>

            <div className="border rounded p-3">
              <p className="font-medium text-sm">Microsoft Intune Setup</p>
              <p className="text-xs text-muted-foreground mt-1">
                1. In Azure AD, register a new application
                <br />
                2. Grant &quot;DeviceManagementManagedDevices.Read.All&quot; API permission
                <br />
                3. Create a client secret
                <br />
                4. Note your Tenant ID, Client ID, and Client Secret
              </p>
            </div>

            <div className="border rounded p-3">
              <p className="font-medium text-sm">VMware Workspace ONE Setup</p>
              <p className="text-xs text-muted-foreground mt-1">
                1. In Workspace ONE UEM Console, go to Groups &amp; Settings &gt; System &gt; Advanced &gt; API
                <br />
                2. Enable API Access and generate an API key
                <br />
                3. Create a service account with read permissions
                <br />
                4. Enter your API server URL and credentials
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function MobileSecurityPage() {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Mobile &amp; Remote Worker Security</h1>
        <p className="text-muted-foreground">
          Mobile threat defense, device posture, ZTNA policy evaluation, and remote worker risk scoring
        </p>
      </div>

      <Tabs defaultValue="dashboard">
        <TabsList>
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="devices">Devices</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          <TabsTrigger value="ztna">ZTNA Policies</TabsTrigger>
          <TabsTrigger value="sessions">Remote Sessions</TabsTrigger>
          <TabsTrigger value="mdm">MDM Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard">
          <DashboardTab />
        </TabsContent>
        <TabsContent value="devices">
          <DevicesTab />
        </TabsContent>
        <TabsContent value="threats">
          <ThreatsTab />
        </TabsContent>
        <TabsContent value="ztna">
          <ZtnaTab />
        </TabsContent>
        <TabsContent value="sessions">
          <SessionsTab />
        </TabsContent>
        <TabsContent value="mdm">
          <MdmTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
