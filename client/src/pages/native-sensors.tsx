import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Server,
  Cpu,
  Activity,
  Wifi,
  WifiOff,
  AlertTriangle,
  Plus,
  Search,
  Trash2,
  Copy,
  Terminal,
  RefreshCw,
  Shield,
  Clock,
  MonitorSmartphone,
  X,
  CheckCircle2,
  Play,
  Pause,
  Zap,
  Network,
  HardDrive,
  Info,
  BookOpen,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Textarea } from "@/components/ui/textarea";

const STATUS_COLORS: Record<string, string> = {
  online: "bg-green-500/10 text-green-500 border-green-500/20",
  offline: "bg-red-500/10 text-red-500 border-red-500/20",
  degraded: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  provisioning: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const LOG_SOURCE_STATUS_COLORS: Record<string, string> = {
  active: "bg-green-500/10 text-green-500 border-green-500/20",
  inactive: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
  error: "bg-red-500/10 text-red-500 border-red-500/20",
  configuring: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const PLATFORM_ICONS: Record<string, string> = {
  linux: "\uD83D\uDC27",
  windows: "\uD83E\uDE9F",
  macos: "\uD83C\uDF4E",
  docker: "\uD83D\uDC33",
  kubernetes: "\u2638\uFE0F",
};

const LOG_SOURCE_TYPE_LABELS: Record<string, { label: string; icon: string; description: string }> = {
  syslog: { label: "Syslog", icon: "\uD83D\uDCE1", description: "RFC 5424/3164 syslog over UDP/TCP" },
  windows_event_log: {
    label: "Windows Event Log",
    icon: "\uD83E\uDE9F",
    description: "Windows Security, System, Application logs",
  },
  http_push: { label: "HTTP Push", icon: "\uD83C\uDF10", description: "JSON/CEF/LEEF over HTTPS webhook" },
  journald: { label: "journald", icon: "\uD83D\uDC27", description: "systemd journal log collection" },
  cloudwatch: { label: "CloudWatch", icon: "\u2601\uFE0F", description: "AWS CloudWatch Logs integration" },
};

const PLATFORM_CAPABILITIES: Record<string, { features: string[]; logSources: string[]; requirements: string }> = {
  linux: {
    features: [
      "Process execution monitoring (execve syscalls)",
      "Network connection tracking (TCP/UDP/ICMP)",
      "File integrity monitoring (inotify)",
      "Authentication log collection (PAM, sshd)",
      "DNS query interception",
      "journald log forwarding",
      "Syslog forwarding (rsyslog/syslog-ng)",
    ],
    logSources: ["syslog", "journald", "http_push"],
    requirements: "Linux kernel 4.15+, glibc 2.17+, systemd (recommended)",
  },
  windows: {
    features: [
      "Process creation monitoring (Sysmon/ETW)",
      "Windows Event Log collection (Security, System, Application, PowerShell)",
      "Network connection tracking (WFP)",
      "File integrity monitoring (NTFS change journal)",
      "Authentication monitoring (LSASS, Kerberos)",
      "Registry change tracking",
      "WMI event subscriptions",
    ],
    logSources: ["windows_event_log", "http_push"],
    requirements: "Windows Server 2016+ or Windows 10+, .NET 4.7.2+, Admin privileges",
  },
  macos: {
    features: [
      "Process execution monitoring (Endpoint Security Framework)",
      "Network connection tracking",
      "File system event monitoring (FSEvents)",
      "Authentication log collection",
      "DNS query monitoring",
      "Unified log collection",
    ],
    logSources: ["syslog", "http_push"],
    requirements: "macOS 10.15+, Full Disk Access TCC approval",
  },
  docker: {
    features: [
      "Container process monitoring",
      "Container network tracking",
      "Image vulnerability scanning",
      "Container file system changes",
      "Docker daemon event monitoring",
      "Container escape detection",
    ],
    logSources: ["http_push", "syslog"],
    requirements: "Docker 20.10+, --pid=host --net=host --privileged flags",
  },
  kubernetes: {
    features: [
      "Pod process monitoring (DaemonSet)",
      "Cluster network policy enforcement",
      "RBAC audit log collection",
      "Container runtime monitoring",
      "Kubernetes API audit logs",
      "Node-level syscall monitoring",
    ],
    logSources: ["http_push", "syslog"],
    requirements: "Kubernetes 1.21+, hostPID + hostNetwork + privileged SecurityContext",
  },
};

interface SensorStats {
  total: number;
  onlineCount: number;
  offlineCount: number;
  degradedCount: number;
  totalEvents: number;
  totalAlerts: number;
}

interface Sensor {
  id: string;
  hostname: string;
  platform: string;
  osVersion: string | null;
  agentVersion: string | null;
  status: string;
  ipAddress: string | null;
  macAddress: string | null;
  tags: string[];
  lastHeartbeat: string | null;
  cpuUsage: number | null;
  memoryUsage: number | null;
  diskUsage: number | null;
  eventsIngested: number;
  alertsGenerated: number;
  createdAt: string;
}

interface LogSource {
  id: string;
  name: string;
  description: string | null;
  sourceType: string;
  status: string;
  sensorId: string | null;
  format: string | null;
  eventsReceived: number;
  eventsDropped: number;
  bytesReceived: number;
  lastEventAt: string | null;
  lastError: string | null;
  listenPort: number | null;
  protocol: string | null;
  httpEndpoint: string | null;
  cloudwatchRegion: string | null;
  cloudwatchLogGroup: string | null;
  createdAt: string;
}

interface RecentEvent {
  id: string;
  logLevel: string | null;
  logSource: string | null;
  logMessage: string | null;
  createdAt: string;
}

function RegisterSensorDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [hostname, setHostname] = useState("");
  const [platform, setPlatform] = useState("linux");
  const [osVersion, setOsVersion] = useState("");
  const [result, setResult] = useState<{ sensor: Sensor; registrationToken: string; apiKey: string } | null>(null);
  const { toast } = useToast();

  const registerMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/native-sensors/register", {
        hostname,
        platform,
        osVersion: osVersion || undefined,
      });
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Sensor registered", description: `${hostname} has been registered successfully.` });
      onSuccess();
    },
    onError: () => {
      toast({ title: "Registration failed", variant: "destructive" });
    },
  });

  const [installCommand, setInstallCommand] = useState<string | null>(null);

  const generateInstall = useMutation({
    mutationFn: async () => {
      if (!result) return;
      const res = await apiRequest("POST", "/api/native-sensors/install-command", {
        platform: result.sensor.platform,
        sensorId: result.sensor.id,
        apiKey: result.apiKey,
      });
      return res.json();
    },
    onSuccess: (data) => {
      if (data) setInstallCommand(data.command);
    },
  });

  return (
    <>
      <Button
        onClick={() => {
          setOpen(true);
          setResult(null);
          setInstallCommand(null);
          setHostname("");
          setPlatform("linux");
          setOsVersion("");
        }}
      >
        <Plus className="h-4 w-4 mr-2" />
        Register Sensor
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>{result ? "Sensor Registered" : "Register New Sensor"}</DialogTitle>
            <DialogDescription>
              {result
                ? "Save these credentials — the API key will not be shown again."
                : "Deploy a lightweight agent on the target host."}
            </DialogDescription>
          </DialogHeader>

          {!result ? (
            <div className="space-y-4">
              <div>
                <Label>Hostname</Label>
                <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="web-server-01" />
              </div>
              <div>
                <Label>Platform</Label>
                <Select value={platform} onValueChange={setPlatform}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="linux">Linux</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="macos">macOS</SelectItem>
                    <SelectItem value="docker">Docker</SelectItem>
                    <SelectItem value="kubernetes">Kubernetes</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>OS Version (optional)</Label>
                <Input value={osVersion} onChange={(e) => setOsVersion(e.target.value)} placeholder="Ubuntu 22.04" />
              </div>
              <div className="rounded-md border p-3 bg-muted/30">
                <div className="text-xs font-medium text-muted-foreground mb-2">
                  {PLATFORM_ICONS[platform]} Platform Capabilities
                </div>
                <div className="space-y-1">
                  {PLATFORM_CAPABILITIES[platform]?.features.slice(0, 4).map((f, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <CheckCircle2 className="h-3 w-3 text-green-500 shrink-0" />
                      {f}
                    </div>
                  ))}
                  {(PLATFORM_CAPABILITIES[platform]?.features.length || 0) > 4 && (
                    <div className="text-xs text-muted-foreground ml-[18px]">
                      +{(PLATFORM_CAPABILITIES[platform]?.features.length || 0) - 4} more capabilities
                    </div>
                  )}
                </div>
                <div className="text-xs text-muted-foreground mt-2 pt-2 border-t">
                  <span className="font-medium">Requires:</span> {PLATFORM_CAPABILITIES[platform]?.requirements}
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={() => registerMutation.mutate()} disabled={!hostname || registerMutation.isPending}>
                  {registerMutation.isPending ? "Registering..." : "Register"}
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="rounded-md bg-muted p-3 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Sensor ID</span>
                  <span className="font-mono text-xs">{result.sensor.id}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Registration Token</span>
                  <span className="font-mono text-xs truncate max-w-[250px]">{result.registrationToken}</span>
                </div>
                <div className="flex justify-between text-sm items-center">
                  <span className="text-muted-foreground">API Key</span>
                  <div className="flex items-center gap-1">
                    <span className="font-mono text-xs truncate max-w-[200px]">{result.apiKey}</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      onClick={() => {
                        navigator.clipboard.writeText(result.apiKey);
                        toast({ title: "Copied API key" });
                      }}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </div>

              {!installCommand ? (
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => generateInstall.mutate()}
                  disabled={generateInstall.isPending}
                >
                  <Terminal className="h-4 w-4 mr-2" />
                  Generate Install Command
                </Button>
              ) : (
                <div className="space-y-2">
                  <Label>Install Command ({result.sensor.platform})</Label>
                  <div className="relative">
                    <pre className="rounded-md bg-zinc-950 text-green-400 p-3 text-xs overflow-x-auto max-h-48 whitespace-pre-wrap">
                      {installCommand}
                    </pre>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="absolute top-1 right-1 h-6 w-6"
                      onClick={() => {
                        navigator.clipboard.writeText(installCommand);
                        toast({ title: "Copied install command" });
                      }}
                    >
                      <Copy className="h-3 w-3 text-white" />
                    </Button>
                  </div>
                </div>
              )}

              <DialogFooter>
                <Button onClick={() => setOpen(false)}>Done</Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function AddLogSourceDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState("syslog");
  const [description, setDescription] = useState("");
  const [format, setFormat] = useState("json");
  const [listenPort, setListenPort] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [cloudwatchRegion, setCloudwatchRegion] = useState("");
  const [cloudwatchLogGroup, setCloudwatchLogGroup] = useState("");
  const { toast } = useToast();

  const createMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        name,
        sourceType,
        description: description || undefined,
        format,
      };
      if (sourceType === "syslog" || sourceType === "journald") {
        body.listenPort = listenPort ? parseInt(listenPort) : undefined;
        body.protocol = protocol;
      }
      if (sourceType === "cloudwatch") {
        body.cloudwatchRegion = cloudwatchRegion || undefined;
        body.cloudwatchLogGroup = cloudwatchLogGroup || undefined;
      }
      const res = await apiRequest("POST", "/api/native/log-sources", body);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Log source created" });
      setOpen(false);
      onSuccess();
    },
    onError: () => {
      toast({ title: "Failed to create log source", variant: "destructive" });
    },
  });

  return (
    <>
      <Button
        variant="outline"
        onClick={() => {
          setOpen(true);
          setName("");
          setDescription("");
        }}
      >
        <Plus className="h-4 w-4 mr-2" />
        Add Log Source
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Log Source</DialogTitle>
            <DialogDescription>Configure a new log ingestion source to collect events directly.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="production-syslog" />
            </div>
            <div>
              <Label>Source Type</Label>
              <Select value={sourceType} onValueChange={setSourceType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(LOG_SOURCE_TYPE_LABELS).map(([key, meta]) => (
                    <SelectItem key={key} value={key}>
                      <span className="flex items-center gap-2">
                        <span>{meta.icon}</span>
                        <span>{meta.label}</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">{LOG_SOURCE_TYPE_LABELS[sourceType]?.description}</p>
            </div>
            <div>
              <Label>Description (optional)</Label>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Describe where this log source collects from..."
                rows={2}
              />
            </div>
            <div>
              <Label>Log Format</Label>
              <Select value={format} onValueChange={setFormat}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="cef">CEF (Common Event Format)</SelectItem>
                  <SelectItem value="leef">LEEF (Log Event Extended Format)</SelectItem>
                  <SelectItem value="raw">Raw Text</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="key_value">Key=Value</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {(sourceType === "syslog" || sourceType === "journald") && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Listen Port</Label>
                  <Input
                    type="number"
                    value={listenPort}
                    onChange={(e) => setListenPort(e.target.value)}
                    placeholder={sourceType === "syslog" ? "514" : "19531"}
                  />
                </div>
                <div>
                  <Label>Protocol</Label>
                  <Select value={protocol} onValueChange={setProtocol}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="tcp">TCP</SelectItem>
                      <SelectItem value="udp">UDP</SelectItem>
                      <SelectItem value="tls">TLS</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}

            {sourceType === "cloudwatch" && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>AWS Region</Label>
                  <Input
                    value={cloudwatchRegion}
                    onChange={(e) => setCloudwatchRegion(e.target.value)}
                    placeholder="us-east-1"
                  />
                </div>
                <div>
                  <Label>Log Group</Label>
                  <Input
                    value={cloudwatchLogGroup}
                    onChange={(e) => setCloudwatchLogGroup(e.target.value)}
                    placeholder="/aws/lambda/my-function"
                  />
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMutation.mutate()} disabled={!name || createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create Source"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function DeploymentGuide() {
  const [selectedPlatform, setSelectedPlatform] = useState("linux");
  const caps = PLATFORM_CAPABILITIES[selectedPlatform];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <BookOpen className="h-4 w-4" />
          Deployment Guide
        </CardTitle>
        <CardDescription>Per-platform capability breakdown and deployment requirements</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex gap-2 mb-4 flex-wrap">
          {Object.entries(PLATFORM_ICONS).map(([platform, icon]) => (
            <Button
              key={platform}
              variant={selectedPlatform === platform ? "default" : "outline"}
              size="sm"
              onClick={() => setSelectedPlatform(platform)}
              className="gap-1.5"
            >
              <span>{icon}</span>
              <span className="capitalize">{platform}</span>
            </Button>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-3">
            <h4 className="text-sm font-medium flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5 text-blue-500" />
              Telemetry Capabilities
            </h4>
            <div className="space-y-1.5">
              {caps?.features.map((feature, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-500 mt-0.5 shrink-0" />
                  <span className="text-muted-foreground">{feature}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-sm font-medium flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5 text-violet-500" />
              Compatible Log Sources
            </h4>
            <div className="space-y-1.5">
              {caps?.logSources.map((src) => {
                const meta = LOG_SOURCE_TYPE_LABELS[src];
                return (
                  <div key={src} className="flex items-center gap-2 text-sm">
                    <span>{meta?.icon}</span>
                    <span className="text-muted-foreground">{meta?.label}</span>
                    <span className="text-xs text-muted-foreground/60">{meta?.description}</span>
                  </div>
                );
              })}
            </div>

            <div className="mt-4 pt-3 border-t">
              <h4 className="text-sm font-medium flex items-center gap-1.5 mb-2">
                <Info className="h-3.5 w-3.5 text-amber-500" />
                System Requirements
              </h4>
              <p className="text-sm text-muted-foreground">{caps?.requirements}</p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function LogSourceConfigPanel() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [selectedSource, setSelectedSource] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["/api/native/log-sources"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native/log-sources");
      return res.json();
    },
  });

  const { data: sourceDetail } = useQuery({
    queryKey: ["/api/native/log-sources", selectedSource],
    queryFn: async () => {
      if (!selectedSource) return null;
      const res = await apiRequest("GET", `/api/native/log-sources/${selectedSource}`);
      return res.json();
    },
    enabled: !!selectedSource,
  });

  const { data: configSnippet } = useQuery({
    queryKey: ["/api/native/log-sources", selectedSource, "config"],
    queryFn: async () => {
      if (!selectedSource) return null;
      const res = await apiRequest("GET", `/api/native/log-sources/${selectedSource}/config`);
      return res.json();
    },
    enabled: !!selectedSource,
  });

  const toggleMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/native/log-sources/${id}/toggle`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/log-sources"] });
      toast({ title: "Log source toggled" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/native/log-sources/${id}/test`);
      return res.json();
    },
    onSuccess: (data) => {
      toast({
        title: data.status === "success" ? "Test passed" : "Test failed",
        description: data.message,
        variant: data.status === "success" ? "default" : "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/native/log-sources/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/log-sources"] });
      setSelectedSource(null);
      toast({ title: "Log source deleted" });
    },
  });

  const sources: LogSource[] = data?.sources || [];
  const stats = data?.stats || { total: 0, totalEvents: 0, totalBytes: 0, activeCount: 0, errorCount: 0 };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Sources</div>
            <div className="text-xl font-semibold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Active</div>
            <div className="text-xl font-semibold text-green-500">{stats.activeCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Errors</div>
            <div className="text-xl font-semibold text-red-500">{stats.errorCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Events Received</div>
            <div className="text-xl font-semibold">{stats.totalEvents.toLocaleString()}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-2">
            <div className="text-xs text-muted-foreground">Data Ingested</div>
            <div className="text-xl font-semibold">{formatBytes(stats.totalBytes)}</div>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : sources.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center">
            <HardDrive className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
            <h3 className="text-base font-medium">No log sources configured</h3>
            <p className="text-muted-foreground text-sm mt-1 max-w-md mx-auto">
              Add a log source to start ingesting syslog, Windows Event Logs, HTTP webhooks, journald, or CloudWatch
              logs directly.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {sources.map((source) => {
            const meta = LOG_SOURCE_TYPE_LABELS[source.sourceType];
            return (
              <Card
                key={source.id}
                className={`cursor-pointer transition-colors hover:bg-muted/50 ${selectedSource === source.id ? "ring-1 ring-primary" : ""}`}
                onClick={() => setSelectedSource(selectedSource === source.id ? null : source.id)}
              >
                <CardContent className="py-3 px-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-lg">{meta?.icon || "\uD83D\uDCE6"}</span>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm">{source.name}</span>
                          <Badge variant="outline" className={LOG_SOURCE_STATUS_COLORS[source.status] || ""}>
                            {source.status}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {meta?.label || source.sourceType}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                          {source.description && <span>{source.description}</span>}
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            Last event: {timeAgo(source.lastEventAt)}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <div className="text-right">
                        <div className="text-muted-foreground text-xs">Events</div>
                        <div className="font-medium">{source.eventsReceived.toLocaleString()}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-muted-foreground text-xs">Data</div>
                        <div className="font-medium">{formatBytes(source.bytesReceived)}</div>
                      </div>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleMutation.mutate(source.id);
                          }}
                          title={source.status === "active" ? "Pause" : "Activate"}
                        >
                          {source.status === "active" ? (
                            <Pause className="h-3.5 w-3.5" />
                          ) : (
                            <Play className="h-3.5 w-3.5" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={(e) => {
                            e.stopPropagation();
                            testMutation.mutate(source.id);
                          }}
                          title="Test connectivity"
                        >
                          <Zap className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {selectedSource && sourceDetail?.source && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <CardTitle className="text-base">{sourceDetail.source.name} — Configuration</CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant="destructive"
                size="sm"
                onClick={() => {
                  if (confirm("Delete this log source? Ingested events will remain.")) {
                    deleteMutation.mutate(selectedSource);
                  }
                }}
              >
                <Trash2 className="h-3 w-3 mr-1" /> Delete
              </Button>
              <Button variant="ghost" size="icon" onClick={() => setSelectedSource(null)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="config">
              <TabsList>
                <TabsTrigger value="config">Setup Instructions</TabsTrigger>
                <TabsTrigger value="events">Recent Events</TabsTrigger>
              </TabsList>
              <TabsContent value="config" className="mt-4">
                {configSnippet?.configs ? (
                  <div className="space-y-4">
                    {Object.entries(configSnippet.configs).map(([label, snippet]) => (
                      <div key={label}>
                        <div className="flex items-center justify-between mb-1">
                          <Label className="capitalize">{label.replace(/_/g, " ")}</Label>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-xs"
                            onClick={() => {
                              navigator.clipboard.writeText(String(snippet));
                              toast({ title: `Copied ${label} config` });
                            }}
                          >
                            <Copy className="h-3 w-3 mr-1" /> Copy
                          </Button>
                        </div>
                        <pre className="rounded-md bg-zinc-950 text-green-400 p-3 text-xs overflow-x-auto max-h-64 whitespace-pre-wrap">
                          {String(snippet)}
                        </pre>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">Loading configuration snippets...</p>
                )}
              </TabsContent>
              <TabsContent value="events" className="mt-4">
                {(sourceDetail.recentEvents || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground py-4 text-center">
                    No events received from this log source yet.
                  </p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {(sourceDetail.recentEvents || []).map((evt: RecentEvent) => (
                      <div key={evt.id} className="rounded-md border p-2.5 text-xs">
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[10px]">
                              {evt.logLevel || "info"}
                            </Badge>
                            <span className="text-muted-foreground">{evt.logSource}</span>
                          </div>
                          <span className="text-muted-foreground">{timeAgo(evt.createdAt)}</span>
                        </div>
                        <p className="text-muted-foreground truncate">{evt.logMessage || "No message"}</p>
                      </div>
                    ))}
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

export default function NativeSensorsPage() {
  usePageTitle("Native Sensors");
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [platformFilter, setPlatformFilter] = useState("all");
  const [selectedSensor, setSelectedSensor] = useState<string | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/native-sensors", search, statusFilter, platformFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (platformFilter !== "all") params.set("platform", platformFilter);
      const res = await apiRequest("GET", `/api/native-sensors?${params}`);
      return res.json();
    },
  });

  const { data: sensorDetail } = useQuery({
    queryKey: ["/api/native-sensors", selectedSensor],
    queryFn: async () => {
      if (!selectedSensor) return null;
      const res = await apiRequest("GET", `/api/native-sensors/${selectedSensor}`);
      return res.json();
    },
    enabled: !!selectedSensor,
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/native-sensors/${id}`);
    },
    onSuccess: () => {
      toast({ title: "Sensor deregistered" });
      queryClient.invalidateQueries({ queryKey: ["/api/native-sensors"] });
      setSelectedSensor(null);
    },
  });

  const sensors: Sensor[] = data?.sensors || [];
  const stats: SensorStats = data?.stats || {
    total: 0,
    onlineCount: 0,
    offlineCount: 0,
    degradedCount: 0,
    totalEvents: 0,
    totalAlerts: 0,
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Native Sensors</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Lightweight agents deployed on hosts — no EDR dependency required. Direct log ingestion from syslog, Windows
            Event Log, HTTP push, journald, and CloudWatch.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <RegisterSensorDialog
            onSuccess={() => queryClient.invalidateQueries({ queryKey: ["/api/native-sensors"] })}
          />
        </div>
      </div>

      <Tabs defaultValue="sensors" className="space-y-4">
        <TabsList>
          <TabsTrigger value="sensors" className="gap-1.5">
            <Cpu className="h-3.5 w-3.5" />
            Sensors
          </TabsTrigger>
          <TabsTrigger value="log-sources" className="gap-1.5">
            <HardDrive className="h-3.5 w-3.5" />
            Log Sources
          </TabsTrigger>
          <TabsTrigger value="deployment" className="gap-1.5">
            <BookOpen className="h-3.5 w-3.5" />
            Deployment Guide
          </TabsTrigger>
        </TabsList>

        <TabsContent value="sensors" className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2">
                  <MonitorSmartphone className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">Total</span>
                </div>
                <p className="text-2xl font-semibold mt-1">
                  {isLoading ? <Skeleton className="h-8 w-12" /> : stats.total}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2">
                  <Wifi className="h-4 w-4 text-green-500" />
                  <span className="text-sm text-muted-foreground">Online</span>
                </div>
                <p className="text-2xl font-semibold mt-1 text-green-500">
                  {isLoading ? <Skeleton className="h-8 w-12" /> : stats.onlineCount}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2">
                  <WifiOff className="h-4 w-4 text-red-500" />
                  <span className="text-sm text-muted-foreground">Offline</span>
                </div>
                <p className="text-2xl font-semibold mt-1 text-red-500">
                  {isLoading ? <Skeleton className="h-8 w-12" /> : stats.offlineCount}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm text-muted-foreground">Degraded</span>
                </div>
                <p className="text-2xl font-semibold mt-1 text-yellow-500">
                  {isLoading ? <Skeleton className="h-8 w-12" /> : stats.degradedCount}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-blue-500" />
                  <span className="text-sm text-muted-foreground">Events</span>
                </div>
                <p className="text-2xl font-semibold mt-1">
                  {isLoading ? <Skeleton className="h-8 w-12" /> : stats.totalEvents.toLocaleString()}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-orange-500" />
                  <span className="text-sm text-muted-foreground">Alerts</span>
                </div>
                <p className="text-2xl font-semibold mt-1 text-orange-500">
                  {isLoading ? <Skeleton className="h-8 w-12" /> : stats.totalAlerts}
                </p>
              </CardContent>
            </Card>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by hostname or IP..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="online">Online</SelectItem>
                <SelectItem value="offline">Offline</SelectItem>
                <SelectItem value="degraded">Degraded</SelectItem>
                <SelectItem value="provisioning">Provisioning</SelectItem>
              </SelectContent>
            </Select>
            <Select value={platformFilter} onValueChange={setPlatformFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Platform" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Platforms</SelectItem>
                <SelectItem value="linux">Linux</SelectItem>
                <SelectItem value="windows">Windows</SelectItem>
                <SelectItem value="macos">macOS</SelectItem>
                <SelectItem value="docker">Docker</SelectItem>
                <SelectItem value="kubernetes">Kubernetes</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {isLoading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-20 w-full" />
              ))}
            </div>
          ) : sensors.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Server className="h-12 w-12 mx-auto text-muted-foreground mb-3" />
                <h3 className="text-lg font-medium">No sensors registered</h3>
                <p className="text-muted-foreground text-sm mt-1">
                  Register your first sensor to start collecting telemetry from hosts.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {sensors.map((sensor) => (
                <Card
                  key={sensor.id}
                  className={`cursor-pointer transition-colors hover:bg-muted/50 ${selectedSensor === sensor.id ? "ring-1 ring-primary" : ""}`}
                  onClick={() => setSelectedSensor(selectedSensor === sensor.id ? null : sensor.id)}
                >
                  <CardContent className="py-3 px-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-xl">{PLATFORM_ICONS[sensor.platform] || "\uD83D\uDDA5\uFE0F"}</span>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{sensor.hostname}</span>
                            <Badge variant="outline" className={STATUS_COLORS[sensor.status] || ""}>
                              {sensor.status}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                            <span>
                              {sensor.platform}
                              {sensor.osVersion ? ` (${sensor.osVersion})` : ""}
                            </span>
                            {sensor.ipAddress && <span>{sensor.ipAddress}</span>}
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {timeAgo(sensor.lastHeartbeat)}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-sm">
                        <div className="text-right">
                          <div className="text-muted-foreground text-xs">Events</div>
                          <div className="font-medium">{sensor.eventsIngested.toLocaleString()}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-muted-foreground text-xs">Alerts</div>
                          <div className="font-medium text-orange-500">{sensor.alertsGenerated}</div>
                        </div>
                        {sensor.cpuUsage !== null && (
                          <div className="text-right">
                            <div className="text-muted-foreground text-xs">CPU</div>
                            <div className="font-medium">{Math.round(sensor.cpuUsage)}%</div>
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {selectedSensor && sensorDetail?.sensor && (
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-3">
                <CardTitle className="text-lg">{sensorDetail.sensor.hostname} — Detail</CardTitle>
                <div className="flex items-center gap-2">
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => {
                      if (confirm("Deregister this sensor? Events and alerts will be orphaned.")) {
                        deleteMutation.mutate(selectedSensor);
                      }
                    }}
                  >
                    <Trash2 className="h-3 w-3 mr-1" /> Deregister
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => setSelectedSensor(null)}>
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="overview">
                  <TabsList>
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="alerts">Recent Alerts</TabsTrigger>
                  </TabsList>
                  <TabsContent value="overview" className="mt-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div>
                        <div className="text-xs text-muted-foreground">Total Events</div>
                        <div className="text-xl font-semibold">
                          {(sensorDetail.eventStats?.totalEvents || 0).toLocaleString()}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-muted-foreground">Matched Events</div>
                        <div className="text-xl font-semibold text-orange-500">
                          {sensorDetail.eventStats?.matchedEvents || 0}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-muted-foreground">Events (24h)</div>
                        <div className="text-xl font-semibold">{sensorDetail.eventStats?.events24h || 0}</div>
                      </div>
                      <div>
                        <div className="text-xs text-muted-foreground">Agent Version</div>
                        <div className="text-xl font-semibold">{sensorDetail.sensor.agentVersion || "—"}</div>
                      </div>
                    </div>
                    {(sensorDetail.sensor.cpuUsage !== null ||
                      sensorDetail.sensor.memoryUsage !== null ||
                      sensorDetail.sensor.diskUsage !== null) && (
                      <div className="grid grid-cols-3 gap-4 mt-4">
                        {sensorDetail.sensor.cpuUsage !== null && (
                          <div>
                            <div className="text-xs text-muted-foreground mb-1">CPU Usage</div>
                            <div className="w-full bg-muted rounded-full h-2">
                              <div
                                className="bg-blue-500 h-2 rounded-full"
                                style={{ width: `${Math.min(sensorDetail.sensor.cpuUsage, 100)}%` }}
                              />
                            </div>
                            <div className="text-xs mt-0.5">{Math.round(sensorDetail.sensor.cpuUsage)}%</div>
                          </div>
                        )}
                        {sensorDetail.sensor.memoryUsage !== null && (
                          <div>
                            <div className="text-xs text-muted-foreground mb-1">Memory</div>
                            <div className="w-full bg-muted rounded-full h-2">
                              <div
                                className="bg-green-500 h-2 rounded-full"
                                style={{ width: `${Math.min(sensorDetail.sensor.memoryUsage, 100)}%` }}
                              />
                            </div>
                            <div className="text-xs mt-0.5">{Math.round(sensorDetail.sensor.memoryUsage)}%</div>
                          </div>
                        )}
                        {sensorDetail.sensor.diskUsage !== null && (
                          <div>
                            <div className="text-xs text-muted-foreground mb-1">Disk</div>
                            <div className="w-full bg-muted rounded-full h-2">
                              <div
                                className="bg-orange-500 h-2 rounded-full"
                                style={{ width: `${Math.min(sensorDetail.sensor.diskUsage, 100)}%` }}
                              />
                            </div>
                            <div className="text-xs mt-0.5">{Math.round(sensorDetail.sensor.diskUsage)}%</div>
                          </div>
                        )}
                      </div>
                    )}
                  </TabsContent>
                  <TabsContent value="alerts" className="mt-4">
                    {(sensorDetail.recentAlerts || []).length === 0 ? (
                      <p className="text-sm text-muted-foreground py-4 text-center">
                        No detection alerts for this sensor yet.
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {(sensorDetail.recentAlerts || []).map(
                          (alert: {
                            id: string;
                            title: string;
                            severity: string;
                            mitreTactic: string | null;
                            mitreTechnique: string | null;
                            createdAt: string;
                          }) => (
                            <div key={alert.id} className="flex items-center justify-between rounded-md border p-3">
                              <div>
                                <div className="font-medium text-sm">{alert.title}</div>
                                <div className="text-xs text-muted-foreground mt-0.5">
                                  {alert.mitreTactic?.replace(/_/g, " ")}{" "}
                                  {alert.mitreTechnique ? `(${alert.mitreTechnique})` : ""}
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <Badge
                                  variant="outline"
                                  className={
                                    alert.severity === "critical"
                                      ? "bg-red-500/10 text-red-500"
                                      : alert.severity === "high"
                                        ? "bg-orange-500/10 text-orange-500"
                                        : alert.severity === "medium"
                                          ? "bg-yellow-500/10 text-yellow-500"
                                          : "bg-green-500/10 text-green-500"
                                  }
                                >
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
        </TabsContent>

        <TabsContent value="log-sources" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-medium">Log Source Configuration</h2>
              <p className="text-sm text-muted-foreground">
                Ingest logs directly from syslog, Windows Event Log, HTTP webhooks, journald, or CloudWatch — replaces
                Splunk/Wazuh entirely.
              </p>
            </div>
            <AddLogSourceDialog
              onSuccess={() => queryClient.invalidateQueries({ queryKey: ["/api/native/log-sources"] })}
            />
          </div>
          <LogSourceConfigPanel />
        </TabsContent>

        <TabsContent value="deployment" className="space-y-4">
          <DeploymentGuide />
        </TabsContent>
      </Tabs>
    </div>
  );
}
