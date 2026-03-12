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
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  Monitor,
  Server,
  Globe,
  Activity,
  Shield,
  Plus,
  Copy,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Cpu,
  HardDrive,
  Network,
  Terminal,
  Download,
  Trash2,
  RefreshCw,
  Eye,
  Wifi,
  WifiOff,
  Box,
  Package,
  ChevronRight,
  Zap,
  ShieldCheck,
  BarChart3,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface NativeSensor {
  id: string;
  hostname: string;
  displayName?: string;
  platform: string;
  sensorType: string;
  status: string;
  agentVersion?: string;
  ipAddress?: string;
  environment: string;
  capabilities: string[];
  tags: string[];
  lastHeartbeatAt?: string;
  lastEventAt?: string;
  eventsLast24h: number;
  alertsLast24h: number;
  osVersion?: string;
  createdAt: string;
}

interface RegisterResponse {
  sensorId: string;
  hostname: string;
  registrationToken: string;
  tokenExpiresAt: string;
  agentInstallInstructions: Record<string, string>;
}

interface PlatformStats {
  sensors: { total: number; online: number; offline: number; degraded: number };
  events: { last24h: number; last7d: number };
  detectionRules: { total: number; active: number; builtin: number };
  coverageNote: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PLATFORM_ICONS: Record<string, React.ReactNode> = {
  linux: <Server className="h-4 w-4" />,
  windows: <Monitor className="h-4 w-4" />,
  macos: <Monitor className="h-4 w-4" />,
  docker: <Box className="h-4 w-4" />,
  kubernetes: <Package className="h-4 w-4" />,
};

function statusColor(status: string) {
  switch (status) {
    case "online":
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    case "degraded":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    case "offline":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    default:
      return "bg-slate-500/10 text-slate-400 border-slate-500/20";
  }
}

function statusDot(status: string) {
  switch (status) {
    case "online":
      return "bg-emerald-400 shadow-emerald-400/50 shadow-sm animate-pulse";
    case "degraded":
      return "bg-yellow-400";
    case "offline":
      return "bg-red-500";
    default:
      return "bg-slate-500";
  }
}

function formatRelativeTime(ts?: string) {
  if (!ts) return "never";
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({
  icon,
  label,
  value,
  sub,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  color: string;
}) {
  return (
    <Card className="bg-slate-900/60 border-slate-700/50">
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${color}`}>{icon}</div>
          <div>
            <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
            <p className="text-2xl font-bold text-white">{value}</p>
            {sub && <p className="text-xs text-slate-500">{sub}</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Install instructions dialog ──────────────────────────────────────────────

function InstallInstructionsDialog({
  data,
  platform,
  onClose,
}: {
  data: RegisterResponse;
  platform: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const { toast } = useToast();

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      toast({ title: "Copied to clipboard" });
      setTimeout(() => setCopied(null), 2000);
    });
  }

  const instructions = data.agentInstallInstructions ?? {};

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-w-2xl bg-slate-900 border-slate-700">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-white">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            Sensor Registered — Install Agent
          </DialogTitle>
          <DialogDescription className="text-slate-400">
            Sensor ID: <code className="text-cyan-400">{data.sensorId}</code>. Copy the registration token
            and deploy the agent on <strong className="text-white">{data.hostname}</strong>.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Token */}
          <div className="space-y-1">
            <Label className="text-slate-300 text-xs uppercase tracking-wider">Registration Token</Label>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-slate-800 border border-slate-600 rounded px-3 py-2 text-xs text-emerald-300 font-mono truncate">
                {data.registrationToken}
              </code>
              <Button
                size="sm"
                variant="outline"
                className="border-slate-600 text-slate-300 hover:text-white shrink-0"
                onClick={() => copyText(data.registrationToken, "token")}
              >
                {copied === "token" ? <CheckCircle2 className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              </Button>
            </div>
            <p className="text-xs text-amber-400">Store this token securely — it will not be shown again.</p>
          </div>

          {/* Install commands */}
          {Object.entries(instructions).map(([key, cmd]) => (
            <div key={key} className="space-y-1">
              <Label className="text-slate-300 text-xs uppercase tracking-wider">{key.replace(/_/g, " ")}</Label>
              <div className="relative">
                <pre className="bg-slate-800 border border-slate-600 rounded p-3 text-xs text-slate-200 font-mono overflow-x-auto whitespace-pre-wrap">
                  {cmd}
                </pre>
                <Button
                  size="sm"
                  variant="ghost"
                  className="absolute top-2 right-2 h-6 w-6 p-0 text-slate-400 hover:text-white"
                  onClick={() => copyText(cmd, key)}
                >
                  {copied === key ? <CheckCircle2 className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                </Button>
              </div>
            </div>
          ))}
        </div>

        <DialogFooter>
          <Button onClick={onClose} className="bg-cyan-600 hover:bg-cyan-700 text-white">
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Register Sensor Dialog ────────────────────────────────────────────────────

function RegisterSensorDialog({ onSuccess }: { onSuccess: (data: RegisterResponse) => void }) {
  const [open, setOpen] = useState(false);
  const [hostname, setHostname] = useState("");
  const [platform, setPlatform] = useState<string>("linux");
  const [sensorType, setSensorType] = useState<string>("endpoint");
  const [environment, setEnvironment] = useState<string>("production");
  const { toast } = useToast();

  const registerMutation = useMutation({
    mutationFn: (body: object) =>
      apiRequest("POST", "/api/native/sensors/register", body).then((r) => r.json()),
    onSuccess: (data) => {
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["/api/native/sensors"] });
      queryClient.invalidateQueries({ queryKey: ["/api/native/stats"] });
      onSuccess(data.data ?? data);
    },
    onError: (err: any) => {
      toast({ title: "Registration failed", description: err.message, variant: "destructive" });
    },
  });

  function submit() {
    if (!hostname.trim()) {
      toast({ title: "Hostname required", variant: "destructive" });
      return;
    }
    registerMutation.mutate({ hostname: hostname.trim(), platform, sensorType, environment });
  }

  return (
    <>
      <Button
        className="bg-cyan-600 hover:bg-cyan-700 text-white gap-2"
        onClick={() => setOpen(true)}
      >
        <Plus className="h-4 w-4" />
        Register Sensor
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="bg-slate-900 border-slate-700 max-w-md">
          <DialogHeader>
            <DialogTitle className="text-white">Register New Sensor</DialogTitle>
            <DialogDescription className="text-slate-400">
              Generate a registration token for a new endpoint agent.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-1">
              <Label className="text-slate-300">Hostname</Label>
              <Input
                placeholder="e.g. prod-server-01"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                onKeyDown={(e) => e.key === "Enter" && submit()}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-slate-300">Platform</Label>
                <Select value={platform} onValueChange={setPlatform}>
                  <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    {["linux", "windows", "macos", "docker", "kubernetes"].map((p) => (
                      <SelectItem key={p} value={p} className="text-slate-200 capitalize">
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label className="text-slate-300">Type</Label>
                <Select value={sensorType} onValueChange={setSensorType}>
                  <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    {[
                      { value: "endpoint", label: "Endpoint Agent" },
                      { value: "log_forwarder", label: "Log Forwarder" },
                      { value: "network_tap", label: "Network Tap" },
                      { value: "cloud_sensor", label: "Cloud Sensor" },
                    ].map((t) => (
                      <SelectItem key={t.value} value={t.value} className="text-slate-200">
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-1">
              <Label className="text-slate-300">Environment</Label>
              <Select value={environment} onValueChange={setEnvironment}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-600">
                  {["production", "staging", "dev"].map((e) => (
                    <SelectItem key={e} value={e} className="text-slate-200 capitalize">
                      {e}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" className="text-slate-400 hover:text-white" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              onClick={submit}
              disabled={registerMutation.isPending}
            >
              {registerMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Plus className="h-4 w-4 mr-2" />
              )}
              Register
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── Sensor Row ────────────────────────────────────────────────────────────────

function SensorRow({ sensor }: { sensor: NativeSensor }) {
  const { toast } = useToast();

  const decommissionMutation = useMutation({
    mutationFn: () =>
      apiRequest("DELETE", `/api/native/sensors/${sensor.id}`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/sensors"] });
      toast({ title: "Sensor decommissioned" });
    },
    onError: () => toast({ title: "Failed to decommission", variant: "destructive" }),
  });

  return (
    <div className="flex items-center gap-4 p-4 rounded-lg bg-slate-800/50 border border-slate-700/50 hover:border-slate-600/70 transition-colors group">
      {/* Status dot */}
      <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${statusDot(sensor.status)}`} />

      {/* Platform icon */}
      <div className="text-slate-400 shrink-0">
        {PLATFORM_ICONS[sensor.platform] ?? <Server className="h-4 w-4" />}
      </div>

      {/* Main info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-white text-sm truncate">
            {sensor.displayName ?? sensor.hostname}
          </span>
          <Badge variant="outline" className={`text-xs px-1.5 py-0 ${statusColor(sensor.status)}`}>
            {sensor.status}
          </Badge>
          {sensor.environment !== "production" && (
            <Badge variant="outline" className="text-xs px-1.5 py-0 border-slate-600 text-slate-400">
              {sensor.environment}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-3 mt-0.5 text-xs text-slate-500">
          <span className="capitalize">{sensor.platform}</span>
          {sensor.ipAddress && <span>{sensor.ipAddress}</span>}
          {sensor.agentVersion && <span>v{sensor.agentVersion}</span>}
          <span>Last seen: {formatRelativeTime(sensor.lastHeartbeatAt)}</span>
        </div>
      </div>

      {/* Stats */}
      <div className="hidden md:flex items-center gap-6 text-xs">
        <div className="text-center">
          <p className="text-slate-400 uppercase tracking-wider">Events/24h</p>
          <p className="text-white font-medium">{sensor.eventsLast24h.toLocaleString()}</p>
        </div>
        <div className="text-center">
          <p className="text-slate-400 uppercase tracking-wider">Alerts/24h</p>
          <p className={sensor.alertsLast24h > 0 ? "text-red-400 font-bold" : "text-white font-medium"}>
            {sensor.alertsLast24h}
          </p>
        </div>
      </div>

      {/* Capabilities */}
      <div className="hidden lg:flex items-center gap-1">
        {(sensor.capabilities ?? []).slice(0, 3).map((cap) => (
          <Badge
            key={cap}
            variant="outline"
            className="text-xs px-1.5 py-0 border-slate-700 text-slate-500 capitalize"
          >
            {cap.replace(/_events/, "")}
          </Badge>
        ))}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <Button
          size="sm"
          variant="ghost"
          className="h-7 w-7 p-0 text-slate-400 hover:text-red-400"
          onClick={() => decommissionMutation.mutate()}
          title="Decommission sensor"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function NativeSensorsPage() {
  const [installData, setInstallData] = useState<RegisterResponse | null>(null);
  const [activeTab, setActiveTab] = useState("sensors");
  const { toast } = useToast();

  const { data: statsData, isLoading: statsLoading } = useQuery<{ data: PlatformStats }>({
    queryKey: ["/api/native/stats"],
  });

  const { data: sensorsData, isLoading: sensorsLoading } = useQuery<{ data: NativeSensor[] }>({
    queryKey: ["/api/native/sensors"],
  });

  const seedMutation = useMutation({
    mutationFn: () =>
      apiRequest("POST", "/api/native/detection-rules/seed").then((r) => r.json()),
    onSuccess: (data) => {
      toast({
        title: `Detection rules seeded`,
        description: `${data.seeded ?? 0} rules added, ${data.skipped ?? 0} already present.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/native/stats"] });
    },
    onError: () => toast({ title: "Seed failed", variant: "destructive" }),
  });

  const stats = statsData?.data;
  const sensors = sensorsData?.data ?? [];

  const onlineSensors = sensors.filter((s) => s.status === "online");
  const offlineSensors = sensors.filter((s) => s.status !== "online");

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="h-6 w-6 text-cyan-400" />
            Native Security Sensors
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Deploy lightweight agents — no CrowdStrike, SentinelOne, or Splunk required.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            className="border-slate-600 text-slate-300 hover:text-white gap-2"
            onClick={() => seedMutation.mutate()}
            disabled={seedMutation.isPending}
          >
            {seedMutation.isPending ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <Download className="h-4 w-4" />
            )}
            Seed Detection Rules
          </Button>
          <RegisterSensorDialog onSuccess={setInstallData} />
        </div>
      </div>

      {/* USP Banner */}
      <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              icon: <Zap className="h-5 w-5 text-cyan-400" />,
              title: "Deploy in 15 Minutes",
              desc: "One-line install script for Linux, Windows, macOS, Docker & Kubernetes",
            },
            {
              icon: <ShieldCheck className="h-5 w-5 text-emerald-400" />,
              title: "45+ MITRE ATT&CK Rules",
              desc: "Built-in detection rules covering all major attack techniques. No configuration needed.",
            },
            {
              icon: <BarChart3 className="h-5 w-5 text-violet-400" />,
              title: "Replace $300K/yr Tooling",
              desc: "One platform replaces CrowdStrike + Splunk + Qualys. Native AI correlation included.",
            },
          ].map((item) => (
            <div key={item.title} className="flex items-start gap-3">
              <div className="mt-0.5">{item.icon}</div>
              <div>
                <p className="text-sm font-medium text-white">{item.title}</p>
                <p className="text-xs text-slate-400">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statsLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="bg-slate-900/60 border-slate-700/50">
              <CardContent className="p-4">
                <Skeleton className="h-16 w-full" />
              </CardContent>
            </Card>
          ))
        ) : (
          <>
            <StatCard
              icon={<Wifi className="h-5 w-5 text-emerald-400" />}
              label="Online Sensors"
              value={stats?.sensors.online ?? 0}
              sub={`of ${stats?.sensors.total ?? 0} total`}
              color="bg-emerald-500/10"
            />
            <StatCard
              icon={<Activity className="h-5 w-5 text-cyan-400" />}
              label="Events (24h)"
              value={(stats?.events.last24h ?? 0).toLocaleString()}
              sub="telemetry events"
              color="bg-cyan-500/10"
            />
            <StatCard
              icon={<Shield className="h-5 w-5 text-violet-400" />}
              label="Detection Rules"
              value={stats?.detectionRules.active ?? 0}
              sub={`${stats?.detectionRules.builtin ?? 0} built-in`}
              color="bg-violet-500/10"
            />
            <StatCard
              icon={<WifiOff className="h-5 w-5 text-red-400" />}
              label="Offline"
              value={stats?.sensors.offline ?? 0}
              sub="sensors need attention"
              color="bg-red-500/10"
            />
          </>
        )}
      </div>

      {/* Main content */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-slate-800 border-slate-700">
          <TabsTrigger value="sensors" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Sensors ({sensors.length})
          </TabsTrigger>
          <TabsTrigger value="log-sources" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Log Sources
          </TabsTrigger>
          <TabsTrigger value="deploy" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Deployment Guide
          </TabsTrigger>
        </TabsList>

        {/* Sensors tab */}
        <TabsContent value="sensors" className="space-y-4 mt-4">
          {sensorsLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full rounded-lg" />
              ))}
            </div>
          ) : sensors.length === 0 ? (
            <Card className="bg-slate-900/60 border-slate-700/50 border-dashed">
              <CardContent className="p-12 text-center">
                <Shield className="h-12 w-12 text-slate-600 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-white mb-2">No sensors registered</h3>
                <p className="text-slate-400 text-sm mb-4">
                  Register your first sensor and deploy the SecureNexus agent to start collecting security telemetry.
                </p>
                <RegisterSensorDialog onSuccess={setInstallData} />
              </CardContent>
            </Card>
          ) : (
            <>
              {onlineSensors.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-slate-500 uppercase tracking-wider px-1">Online</p>
                  {onlineSensors.map((s) => (
                    <SensorRow key={s.id} sensor={s} />
                  ))}
                </div>
              )}
              {offlineSensors.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-slate-500 uppercase tracking-wider px-1">Offline / Degraded</p>
                  {offlineSensors.map((s) => (
                    <SensorRow key={s.id} sensor={s} />
                  ))}
                </div>
              )}
            </>
          )}
        </TabsContent>

        {/* Log Sources tab */}
        <TabsContent value="log-sources" className="mt-4">
          <LogSourcesPanel />
        </TabsContent>

        {/* Deploy guide tab */}
        <TabsContent value="deploy" className="mt-4">
          <DeploymentGuide />
        </TabsContent>
      </Tabs>

      {/* Install instructions modal */}
      {installData && (
        <InstallInstructionsDialog
          data={installData}
          platform="linux"
          onClose={() => setInstallData(null)}
        />
      )}
    </div>
  );
}

// ─── Log Sources Panel ────────────────────────────────────────────────────────

function LogSourcesPanel() {
  const { data, isLoading } = useQuery<{ data: any[] }>({
    queryKey: ["/api/native/log-sources"],
  });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState("syslog_udp");
  const [port, setPort] = useState("");
  const { toast } = useToast();

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiRequest("POST", "/api/native/log-sources", body).then((r) => r.json()),
    onSuccess: () => {
      setOpen(false);
      setName("");
      setPort("");
      queryClient.invalidateQueries({ queryKey: ["/api/native/log-sources"] });
      toast({ title: "Log source added" });
    },
    onError: () => toast({ title: "Failed to add log source", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("DELETE", `/api/native/log-sources/${id}`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/log-sources"] });
      toast({ title: "Log source removed" });
    },
  });

  const sources = data?.data ?? [];

  const LOG_SOURCE_LABELS: Record<string, string> = {
    syslog_udp: "Syslog (UDP 514)",
    syslog_tcp: "Syslog (TCP)",
    windows_event_log: "Windows Event Log",
    http_push: "HTTP Push / Webhook",
    file_tail: "File Tail",
    journald: "systemd Journal",
    cloudwatch: "AWS CloudWatch",
    azure_monitor: "Azure Monitor",
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-slate-400 text-sm">
          Ingest syslog, Windows Event Logs, and application logs without a SIEM.
        </p>
        <Button
          className="bg-cyan-600 hover:bg-cyan-700 text-white gap-2"
          size="sm"
          onClick={() => setOpen(true)}
        >
          <Plus className="h-4 w-4" />
          Add Log Source
        </Button>
      </div>

      {isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : sources.length === 0 ? (
        <div className="text-center py-12 text-slate-500">
          <Network className="h-10 w-10 mx-auto mb-3 opacity-40" />
          <p>No log sources configured. Add syslog, Windows Event Log, or HTTP push sources.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {sources.map((src: any) => (
            <div
              key={src.id}
              className="flex items-center gap-4 p-4 rounded-lg bg-slate-800/50 border border-slate-700/50"
            >
              <Network className="h-4 w-4 text-slate-400 shrink-0" />
              <div className="flex-1">
                <p className="text-sm font-medium text-white">{src.name}</p>
                <p className="text-xs text-slate-500">
                  {LOG_SOURCE_LABELS[src.sourceType] ?? src.sourceType}
                  {src.port && ` · Port ${src.port}`}
                </p>
              </div>
              <Badge
                variant="outline"
                className={
                  src.status === "active"
                    ? "border-emerald-500/30 text-emerald-400 text-xs"
                    : "border-slate-600 text-slate-500 text-xs"
                }
              >
                {src.status}
              </Badge>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 text-slate-500 hover:text-red-400"
                onClick={() => deleteMutation.mutate(src.id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}
        </div>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="bg-slate-900 border-slate-700 max-w-md">
          <DialogHeader>
            <DialogTitle className="text-white">Add Log Source</DialogTitle>
            <DialogDescription className="text-slate-400">
              Configure a log ingestion endpoint.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1">
              <Label className="text-slate-300">Name</Label>
              <Input
                placeholder="e.g. Production Syslog"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-slate-300">Type</Label>
              <Select value={sourceType} onValueChange={setSourceType}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-slate-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-600">
                  {Object.entries(LOG_SOURCE_LABELS).map(([v, l]) => (
                    <SelectItem key={v} value={v} className="text-slate-200">
                      {l}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {["syslog_udp", "syslog_tcp"].includes(sourceType) && (
              <div className="space-y-1">
                <Label className="text-slate-300">Port</Label>
                <Input
                  placeholder="514"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" className="text-slate-400 hover:text-white" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              onClick={() =>
                createMutation.mutate({
                  name,
                  sourceType,
                  port: port ? parseInt(port) : undefined,
                })
              }
              disabled={!name || createMutation.isPending}
            >
              Add Source
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Deployment Guide ─────────────────────────────────────────────────────────

function DeploymentGuide() {
  const steps = [
    {
      step: "1",
      title: "Register Sensor",
      desc: "Click 'Register Sensor', pick your platform, and get a unique registration token.",
      icon: <Shield className="h-5 w-5 text-cyan-400" />,
    },
    {
      step: "2",
      title: "Run One-Line Install",
      desc: "Copy the install command and run it on your server. The agent auto-configures itself.",
      icon: <Terminal className="h-5 w-5 text-emerald-400" />,
    },
    {
      step: "3",
      title: "Agent Goes Online",
      desc: "Within 30 seconds your sensor appears online. Telemetry starts flowing immediately.",
      icon: <Wifi className="h-5 w-5 text-violet-400" />,
    },
    {
      step: "4",
      title: "AI Detects Threats",
      desc: "45+ built-in MITRE ATT&CK rules fire on suspicious events. Alerts auto-correlate into incidents.",
      icon: <Zap className="h-5 w-5 text-amber-400" />,
    },
  ];

  const platformDetails = [
    {
      platform: "Linux",
      icon: <Server className="h-6 w-6 text-cyan-400" />,
      features: ["Process events (execve)", "Network connections", "File integrity", "Auth logs (PAM/sshd)", "Cron jobs"],
      footprint: "~8 MB RAM, <1% CPU",
    },
    {
      platform: "Windows",
      icon: <Monitor className="h-6 w-6 text-blue-400" />,
      features: ["ETW event collection", "Registry monitoring", "Service creation", "PowerShell logging", "LSASS protection"],
      footprint: "~20 MB RAM, <2% CPU",
    },
    {
      platform: "macOS",
      icon: <Monitor className="h-6 w-6 text-slate-300" />,
      features: ["Endpoint Security Framework", "Gatekeeper events", "Launch agents/daemons", "Network connections"],
      footprint: "~12 MB RAM, <1% CPU",
    },
    {
      platform: "Kubernetes",
      icon: <Package className="h-6 w-6 text-violet-400" />,
      features: ["DaemonSet deployment", "Pod/container events", "K8s API audit", "Network policy violations", "Image pull events"],
      footprint: "~30 MB RAM per node",
    },
  ];

  return (
    <div className="space-y-8">
      {/* Steps */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {steps.map((s, i) => (
          <div key={s.step} className="relative">
            {i < steps.length - 1 && (
              <div className="hidden md:block absolute top-6 left-full w-full h-px bg-gradient-to-r from-slate-600 to-transparent z-10" />
            )}
            <Card className="bg-slate-900/60 border-slate-700/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-3 mb-2">
                  <div className="h-7 w-7 rounded-full bg-slate-800 border border-slate-600 flex items-center justify-center text-xs font-bold text-slate-300">
                    {s.step}
                  </div>
                  {s.icon}
                </div>
                <h4 className="text-sm font-medium text-white">{s.title}</h4>
                <p className="text-xs text-slate-400 mt-1">{s.desc}</p>
              </CardContent>
            </Card>
          </div>
        ))}
      </div>

      {/* Platform details */}
      <div>
        <h3 className="text-base font-medium text-white mb-3">Agent Capabilities by Platform</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {platformDetails.map((p) => (
            <Card key={p.platform} className="bg-slate-900/60 border-slate-700/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-white">
                  {p.icon}
                  {p.platform}
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">{p.footprint}</CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1">
                  {p.features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-xs text-slate-400">
                      <CheckCircle2 className="h-3 w-3 text-emerald-500 shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
