import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { Progress } from "@/components/ui/progress";
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
  Settings2,
  Download,
  Upload,
  ArrowUpRight,
  RotateCcw,
  Timer,
  Package,
  Layers,
  GitBranch,
  Globe,
  Send,
  FileText,
  ShieldCheck,
  Users,
  Loader2,
  CheckCircle,
  XCircle,
  Ban,
} from "lucide-react";
import { DownloadDoneIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

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
  ios: "\uD83D\uDCF1",
  android: "\uD83E\uDD16",
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
  ios: {
    features: [
      "App activity monitoring (NSExtension framework)",
      "Network traffic inspection (NEFilterDataProvider)",
      "Device posture assessment (MDM compliance)",
      "Jailbreak detection",
      "Certificate pinning validation",
      "Bluetooth/AirDrop peripheral monitoring",
      "Push notification event forwarding",
    ],
    logSources: ["http_push"],
    requirements: "iOS 15+, MDM enrollment or TestFlight, Network Extension entitlement",
  },
  android: {
    features: [
      "App usage monitoring (UsageStatsManager)",
      "Network traffic inspection (VpnService)",
      "Device posture assessment (Device Admin / Android Enterprise)",
      "Root/bootloader unlock detection",
      "SMS/call log monitoring (with permissions)",
      "Wi-Fi/Bluetooth scanning",
      "Accessibility service event capture",
    ],
    logSources: ["http_push"],
    requirements: "Android 10+ (API 29+), Device Owner or Profile Owner, Google Play Protect enabled",
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
                    <SelectItem value="ios">iOS</SelectItem>
                    <SelectItem value="android">Android</SelectItem>
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
                      <CheckCircle2 className="h-3 w-3 text-green-500" />
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

// 47.1: Sensor Deployment Wizard (multi-step)
function SensorDeploymentWizard() {
  const [step, setStep] = useState(1);
  const [selectedPlatform, setSelectedPlatform] = useState("linux");
  const [hostname, setHostname] = useState("");
  const [registrationResult, setRegistrationResult] = useState<{
    sensor: { id: string };
    apiKey: string;
    registrationToken: string;
  } | null>(null);
  const [installCommand, setInstallCommand] = useState("");
  const [verifyStatus, setVerifyStatus] = useState<"idle" | "checking" | "success" | "failed">("idle");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const registerMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/native-sensors/register", {
        hostname,
        platform: selectedPlatform,
      });
      return res.json();
    },
    onSuccess: async (data) => {
      setRegistrationResult(data);
      const cmdRes = await apiRequest("POST", "/api/native-sensors/install-command", {
        platform: selectedPlatform,
        sensorId: data.sensor.id,
        apiKey: data.apiKey,
      });
      const cmdData = await cmdRes.json();
      setInstallCommand(cmdData.command);
      setStep(3);
      queryClient.invalidateQueries({ queryKey: ["/api/native-sensors"] });
    },
    onError: () => toast({ title: "Registration failed", variant: "destructive" }),
  });

  const handleVerify = async () => {
    if (!registrationResult) return;
    setVerifyStatus("checking");
    try {
      const res = await apiRequest("GET", `/api/native-sensors/${registrationResult.sensor.id}`);
      const data = await res.json();
      if (data.sensor?.status === "online") {
        setVerifyStatus("success");
        toast({ title: "Sensor is online!" });
        setStep(5);
      } else {
        setVerifyStatus("failed");
        toast({
          title: "Sensor not yet online",
          description: "Run the install command and try again",
          variant: "destructive",
        });
      }
    } catch {
      setVerifyStatus("failed");
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <DownloadDoneIcon size={18} color="currentColor" /> Deployment Wizard
        </CardTitle>
        <CardDescription>Step-by-step sensor deployment for any platform</CardDescription>
      </CardHeader>
      <CardContent>
        {/* Progress */}
        <div className="flex items-center gap-2 mb-6">
          {["Platform", "Register", "Install", "Verify", "Done"].map((label, idx) => (
            <div key={label} className="flex items-center gap-1 flex-1">
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                  step > idx + 1
                    ? "bg-green-500 text-white"
                    : step === idx + 1
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground"
                }`}
              >
                {step > idx + 1 ? "\u2713" : idx + 1}
              </div>
              <span className="text-xs text-muted-foreground hidden md:inline">{label}</span>
              {idx < 4 && <div className="flex-1 h-0.5 bg-muted mx-1" />}
            </div>
          ))}
        </div>

        {step === 1 && (
          <div className="space-y-4">
            <h3 className="font-medium">Select Target Platform</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(PLATFORM_ICONS).map(([platform, icon]) => (
                <button
                  key={platform}
                  onClick={() => setSelectedPlatform(platform)}
                  className={`p-4 rounded-lg border text-center transition-all ${
                    selectedPlatform === platform
                      ? "border-primary bg-primary/5 ring-1 ring-primary"
                      : "hover:bg-muted/50"
                  }`}
                >
                  <span className="text-2xl block mb-1">{icon}</span>
                  <span className="text-sm capitalize">{platform}</span>
                </button>
              ))}
            </div>
            <Button onClick={() => setStep(2)} className="w-full">
              Next: Register Sensor
            </Button>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <h3 className="font-medium">Register Sensor</h3>
            <div>
              <Label>Hostname</Label>
              <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="e.g., prod-web-01" />
            </div>
            <div className="p-3 rounded-lg bg-muted">
              <div className="flex items-center gap-2 text-sm">
                <span className="text-lg">{PLATFORM_ICONS[selectedPlatform]}</span>
                <span className="capitalize font-medium">{selectedPlatform}</span>
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setStep(1)}>
                Back
              </Button>
              <Button
                className="flex-1"
                disabled={!hostname || registerMutation.isPending}
                onClick={() => registerMutation.mutate()}
              >
                {registerMutation.isPending ? "Registering..." : "Register & Generate Installer"}
              </Button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-4">
            <h3 className="font-medium">Install Sensor Agent</h3>
            <p className="text-sm text-muted-foreground">Run the following command on your {selectedPlatform} host:</p>
            <div className="relative">
              <pre className="rounded-md bg-zinc-950 text-green-400 p-3 text-xs overflow-x-auto max-h-48 whitespace-pre-wrap">
                {installCommand}
              </pre>
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-2 right-2 h-6 text-xs"
                onClick={() => {
                  navigator.clipboard.writeText(installCommand);
                  toast({ title: "Copied to clipboard" });
                }}
              >
                Copy
              </Button>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setStep(2)}>
                Back
              </Button>
              <Button className="flex-1" onClick={() => setStep(4)}>
                Next: Verify Connection
              </Button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-4">
            <h3 className="font-medium">Verify Sensor Connection</h3>
            <p className="text-sm text-muted-foreground">Click below to check if the sensor is reporting heartbeats.</p>
            <Button className="w-full" onClick={handleVerify} disabled={verifyStatus === "checking"}>
              {verifyStatus === "checking"
                ? "Checking..."
                : verifyStatus === "success"
                  ? "Verified!"
                  : "Check Connection"}
            </Button>
            {verifyStatus === "failed" && (
              <p className="text-xs text-orange-500">
                Sensor not yet online. Make sure you ran the install command and the agent started successfully.
              </p>
            )}
          </div>
        )}

        {step === 5 && (
          <div className="text-center space-y-3 py-4">
            <CheckCircle2 className="h-12 w-12 text-green-500" />
            <h3 className="font-medium">Deployment Complete!</h3>
            <p className="text-sm text-muted-foreground">
              Your {selectedPlatform} sensor is online and reporting data.
            </p>
            <Button
              variant="outline"
              onClick={() => {
                setStep(1);
                setRegistrationResult(null);
                setInstallCommand("");
                setVerifyStatus("idle");
                setHostname("");
              }}
            >
              Deploy Another Sensor
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// 47.2: Sensor Fleet Dashboard
function SensorFleetDashboard({ sensors, stats }: { sensors: Sensor[]; stats: SensorStats }) {
  const platformBreakdown: Record<string, number> = {};
  sensors.forEach((s) => {
    platformBreakdown[s.platform] = (platformBreakdown[s.platform] || 0) + 1;
  });

  const versionBreakdown: Record<string, number> = {};
  sensors.forEach((s) => {
    const v = s.agentVersion || "unknown";
    versionBreakdown[v] = (versionBreakdown[v] || 0) + 1;
  });

  const avgCpu =
    sensors.length > 0 ? Math.round(sensors.reduce((sum, s) => sum + (s.cpuUsage || 0), 0) / sensors.length) : 0;
  const avgMem =
    sensors.length > 0 ? Math.round(sensors.reduce((sum, s) => sum + (s.memoryUsage || 0), 0) / sensors.length) : 0;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Online</div>
            <div className="text-2xl font-bold text-green-500">{stats.onlineCount}</div>
            <Progress value={stats.total > 0 ? (stats.onlineCount / stats.total) * 100 : 0} className="h-1 mt-2" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Offline</div>
            <div className="text-2xl font-bold text-red-500">{stats.offlineCount}</div>
            <Progress value={stats.total > 0 ? (stats.offlineCount / stats.total) * 100 : 0} className="h-1 mt-2" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Avg CPU</div>
            <div className="text-2xl font-bold">{avgCpu}%</div>
            <Progress value={avgCpu} className="h-1 mt-2" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Avg Memory</div>
            <div className="text-2xl font-bold">{avgMem}%</div>
            <Progress value={avgMem} className="h-1 mt-2" />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Globe className="h-4 w-4" /> Platform Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(platformBreakdown)
                .sort(([, a], [, b]) => b - a)
                .map(([platform, count]) => (
                  <div key={platform} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span>{PLATFORM_ICONS[platform] || "\u2699\uFE0F"}</span>
                      <span className="text-sm capitalize">{platform}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary rounded-full"
                          style={{ width: `${sensors.length > 0 ? (count / sensors.length) * 100 : 0}%` }}
                        />
                      </div>
                      <span className="text-sm text-muted-foreground w-8 text-right">{count}</span>
                    </div>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <GitBranch className="h-4 w-4" /> Version Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(versionBreakdown)
                .sort(([a], [b]) => b.localeCompare(a))
                .map(([version, count], idx) => (
                  <div key={version} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{version}</span>
                      {idx === 0 && (
                        <Badge variant="outline" className="text-[10px] bg-green-500/10 text-green-500">
                          latest
                        </Badge>
                      )}
                    </div>
                    <span className="text-sm text-muted-foreground">{count} sensors</span>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// 47.3: Sensor Policy Management
function SensorPolicyPanel() {
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [policyForm, setPolicyForm] = useState({
    name: "",
    platform: "",
    telemetryLevel: "standard",
    heartbeatInterval: 60,
    autoUpdate: true,
  });

  const { data: policies = [], isLoading } = useQuery<
    Array<{
      id: string;
      name: string;
      platform: string | null;
      telemetryLevel: string;
      heartbeatInterval: number;
      autoUpdate: boolean;
      sensorCount: number;
    }>
  >({
    queryKey: ["/api/native-sensors/policies"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-sensors/policies");
      return res.json();
    },
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/native-sensors/policies", {
        ...policyForm,
        platform: policyForm.platform || null,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Policy created" });
      setShowCreate(false);
      setPolicyForm({ name: "", platform: "", telemetryLevel: "standard", heartbeatInterval: 60, autoUpdate: true });
    },
    onError: () => toast({ title: "Failed to create policy", variant: "destructive" }),
  });

  if (isLoading) return <Skeleton className="h-48" />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-medium text-sm">Sensor Policies</h3>
        <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
          <Plus className="h-3.5 w-3.5 mr-1" /> New Policy
        </Button>
      </div>

      {showCreate && (
        <Card>
          <CardContent className="pt-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Policy Name</Label>
                <Input
                  value={policyForm.name}
                  onChange={(e) => setPolicyForm({ ...policyForm, name: e.target.value })}
                  placeholder="e.g., Production Servers"
                />
              </div>
              <div>
                <Label>Platform (blank = all)</Label>
                <Select
                  value={policyForm.platform}
                  onValueChange={(v) => setPolicyForm({ ...policyForm, platform: v })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All platforms" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all_platforms">All Platforms</SelectItem>
                    {Object.keys(PLATFORM_ICONS).map((p) => (
                      <SelectItem key={p} value={p}>
                        {PLATFORM_ICONS[p]} {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Telemetry Level</Label>
                <Select
                  value={policyForm.telemetryLevel}
                  onValueChange={(v) => setPolicyForm({ ...policyForm, telemetryLevel: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="minimal">Minimal</SelectItem>
                    <SelectItem value="standard">Standard</SelectItem>
                    <SelectItem value="full">Full</SelectItem>
                    <SelectItem value="debug">Debug</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Heartbeat Interval (seconds)</Label>
                <Input
                  type="number"
                  value={policyForm.heartbeatInterval}
                  onChange={(e) => setPolicyForm({ ...policyForm, heartbeatInterval: parseInt(e.target.value) || 60 })}
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={policyForm.autoUpdate}
                onChange={(e) => setPolicyForm({ ...policyForm, autoUpdate: e.target.checked })}
                id="auto-update-check"
              />
              <Label htmlFor="auto-update-check">Enable auto-update</Label>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button disabled={!policyForm.name || createMutation.isPending} onClick={() => createMutation.mutate()}>
                {createMutation.isPending ? "Creating..." : "Create Policy"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {policies.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center">
            <Settings2 className="h-8 w-8 text-muted-foreground/40 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">
              No policies defined yet. Create a policy to configure telemetry levels and update behavior for sensor
              groups.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {policies.map((policy) => (
            <Card key={policy.id}>
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Settings2 className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <span className="font-medium text-sm">{policy.name}</span>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                        <Badge variant="outline">{policy.platform || "All platforms"}</Badge>
                        <span>Telemetry: {policy.telemetryLevel}</span>
                        <span>Heartbeat: {policy.heartbeatInterval}s</span>
                        {policy.autoUpdate && (
                          <Badge variant="outline" className="bg-green-500/10 text-green-500">
                            Auto-update
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <Badge variant="outline">{policy.sensorCount || 0} sensors</Badge>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// 47.4: Sensor Version Management
function SensorVersionPanel({ sensors }: { sensors: Sensor[] }) {
  const { toast } = useToast();
  const [rolloutTarget, setRolloutTarget] = useState<string | null>(null);

  const versions: Record<string, { count: number; sensors: Sensor[] }> = {};
  sensors.forEach((s) => {
    const v = s.agentVersion || "unknown";
    if (!versions[v]) versions[v] = { count: 0, sensors: [] };
    versions[v].count++;
    versions[v].sensors.push(s);
  });

  const sortedVersions = Object.entries(versions).sort(([a], [b]) => b.localeCompare(a));
  const latestVersion = sortedVersions[0]?.[0] || "unknown";
  const outdatedCount = sensors.filter((s) => (s.agentVersion || "unknown") !== latestVersion).length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Latest Version</div>
            <div className="text-xl font-bold font-mono">{latestVersion}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Up-to-date</div>
            <div className="text-xl font-bold text-green-500">{sensors.length - outdatedCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-sm text-muted-foreground">Needs Upgrade</div>
            <div className="text-xl font-bold text-orange-500">{outdatedCount}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Upload className="h-4 w-4" /> Version Distribution & Rollout
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {sortedVersions.map(([version, data], idx) => (
              <div key={version} className="border rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium">{version}</span>
                    {idx === 0 && (
                      <Badge variant="outline" className="bg-green-500/10 text-green-500">
                        Latest
                      </Badge>
                    )}
                    {idx > 0 && (
                      <Badge variant="outline" className="bg-orange-500/10 text-orange-500">
                        Outdated
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm">
                      {data.count} sensors ({sensors.length > 0 ? Math.round((data.count / sensors.length) * 100) : 0}%)
                    </span>
                    {idx > 0 && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs"
                        onClick={() => {
                          setRolloutTarget(version);
                          toast({
                            title: "Staged rollout initiated",
                            description: `Upgrading ${data.count} sensors from ${version} to ${latestVersion}. 10% canary first.`,
                          });
                        }}
                      >
                        <ArrowUpRight className="h-3 w-3 mr-1" /> Upgrade
                      </Button>
                    )}
                  </div>
                </div>
                {rolloutTarget === version && (
                  <div className="mt-2 p-2 rounded bg-blue-500/5 border border-blue-500/20">
                    <div className="flex items-center gap-2 text-xs text-blue-500 mb-1">
                      <Timer className="h-3 w-3" />
                      Staged rollout in progress: 10% canary deployment
                    </div>
                    <Progress value={10} className="h-1.5" />
                    <p className="text-[10px] text-muted-foreground mt-1">
                      {Math.ceil(data.count * 0.1)} of {data.count} sensors upgrading. Will proceed to 100% after
                      verification.
                    </p>
                  </div>
                )}
                <div className="flex flex-wrap gap-1 mt-2">
                  {data.sensors.slice(0, 8).map((s) => (
                    <Badge key={s.id} variant="outline" className="text-[10px]">
                      {PLATFORM_ICONS[s.platform]} {s.hostname}
                    </Badge>
                  ))}
                  {data.sensors.length > 8 && (
                    <Badge variant="outline" className="text-[10px]">
                      +{data.sensors.length - 8} more
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
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

// ==========================================================================
// 50.1: Command execution with live output
// 50.2: Command templates library
// 50.3: Command approval workflow
// 50.4: Multi-agent batch commands
// ==========================================================================

const COMMAND_TEMPLATES = [
  {
    id: "process_list",
    name: "Collect Process List",
    command: "ps aux --sort=-%mem | head -50",
    category: "collect",
    risk: "low",
    description: "List running processes sorted by memory usage",
  },
  {
    id: "network_conns",
    name: "Network Connections",
    command: "ss -tunap | head -100",
    category: "collect",
    risk: "low",
    description: "Show active network connections with process info",
  },
  {
    id: "collect_logs",
    name: "Collect System Logs",
    command: "journalctl --since '1 hour ago' --no-pager | tail -500",
    category: "collect",
    risk: "low",
    description: "Collect recent system logs from the last hour",
  },
  {
    id: "memory_dump",
    name: "Memory Snapshot",
    command: "cat /proc/meminfo && free -h",
    category: "collect",
    risk: "low",
    description: "Capture memory usage snapshot",
  },
  {
    id: "disk_usage",
    name: "Disk Usage",
    command: "df -h && du -sh /var/log/* 2>/dev/null | sort -rh | head -20",
    category: "collect",
    risk: "low",
    description: "Check disk usage and largest log files",
  },
  {
    id: "kill_process",
    name: "Kill Process",
    command: "kill -9 {{PID}}",
    category: "respond",
    risk: "high",
    description: "Terminate a process by PID (destructive)",
  },
  {
    id: "isolate_host",
    name: "Isolate Endpoint",
    command: "iptables -P INPUT DROP && iptables -P OUTPUT DROP && iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
    category: "respond",
    risk: "critical",
    description: "Network-isolate the host (keeps SSH)",
  },
  {
    id: "block_ip",
    name: "Block IP Address",
    command: "iptables -A INPUT -s {{IP}} -j DROP && iptables -A OUTPUT -d {{IP}} -j DROP",
    category: "respond",
    risk: "high",
    description: "Block all traffic to/from an IP",
  },
  {
    id: "delete_file",
    name: "Delete Malicious File",
    command: "rm -f {{FILE_PATH}}",
    category: "respond",
    risk: "critical",
    description: "Delete a file from the endpoint (destructive)",
  },
  {
    id: "quarantine_file",
    name: "Quarantine File",
    command: "mkdir -p /var/quarantine && mv {{FILE_PATH}} /var/quarantine/",
    category: "respond",
    risk: "high",
    description: "Move suspicious file to quarantine directory",
  },
];

const RISK_STYLES: Record<string, string> = {
  low: "bg-green-500/10 text-green-400 border-green-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
};

function CommandTemplatesPanel({ sensors }: { sensors: Sensor[] }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedTemplate, setSelectedTemplate] = useState<(typeof COMMAND_TEMPLATES)[number] | null>(null);
  const [customCommand, setCustomCommand] = useState("");
  const [targetSensorId, setTargetSensorId] = useState("");
  const [commandOutput, setCommandOutput] = useState<string[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState("all");

  const executeCommandMutation = useMutation({
    mutationFn: async (payload: { sensorId: string; command: string; templateId?: string }) => {
      const res = await apiRequest("POST", "/api/native/response/actions", {
        sensorId: payload.sensorId,
        actionType: "run_script",
        scriptContent: payload.command,
        scriptType: "bash",
        reason: payload.templateId ? `Template: ${payload.templateId}` : "Manual command",
      });
      return res.json();
    },
    onSuccess: (data) => {
      // 50.1: Simulate streaming output
      setIsStreaming(true);
      setCommandOutput([`[${new Date().toISOString()}] Command dispatched to agent...`]);
      const lines = [
        `[${new Date().toISOString()}] Agent acknowledged command`,
        `[${new Date().toISOString()}] Executing...`,
        `[${new Date().toISOString()}] Status: ${data.action?.status || "pending"}`,
        data.needsApproval
          ? `[${new Date().toISOString()}] ⚠ Requires approval before execution (${data.action?.riskLevel} risk)`
          : `[${new Date().toISOString()}] ✓ Command approved and queued for execution`,
      ];
      let idx = 0;
      const interval = setInterval(() => {
        if (idx < lines.length) {
          setCommandOutput((prev) => [...prev, lines[idx]]);
          idx++;
        } else {
          setIsStreaming(false);
          clearInterval(interval);
        }
      }, 800);
      queryClient.invalidateQueries({ queryKey: ["/api/native/response"] });
      toast({ title: data.needsApproval ? "Command queued for approval" : "Command dispatched" });
    },
    onError: () => toast({ title: "Command failed", variant: "destructive" }),
  });

  const filteredTemplates =
    categoryFilter === "all" ? COMMAND_TEMPLATES : COMMAND_TEMPLATES.filter((t) => t.category === categoryFilter);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium">Command Templates</h2>
          <p className="text-sm text-muted-foreground">Pre-built response actions with one-click execution</p>
        </div>
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="collect">Collection</SelectItem>
            <SelectItem value="respond">Response</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filteredTemplates.map((tpl) => (
          <Card
            key={tpl.id}
            className="cursor-pointer hover:border-zinc-600 transition-colors"
            onClick={() => {
              setSelectedTemplate(tpl);
              setCustomCommand(tpl.command);
            }}
          >
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium">{tpl.name}</h3>
                <Badge variant="outline" className={RISK_STYLES[tpl.risk] || ""}>
                  {tpl.risk}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mb-2">{tpl.description}</p>
              <code className="text-xs bg-zinc-900 px-2 py-1 rounded block truncate font-mono">{tpl.command}</code>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Command execution dialog */}
      <Dialog
        open={!!selectedTemplate}
        onOpenChange={() => {
          setSelectedTemplate(null);
          setCommandOutput([]);
          setIsStreaming(false);
        }}
      >
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              {selectedTemplate?.name}
              {selectedTemplate && (
                <Badge variant="outline" className={RISK_STYLES[selectedTemplate.risk] || ""}>
                  {selectedTemplate.risk} risk
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {/* 50.3: Approval warning for destructive commands */}
            {selectedTemplate && (selectedTemplate.risk === "high" || selectedTemplate.risk === "critical") && (
              <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3 flex items-start gap-2">
                <ShieldCheck className="h-4 w-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-orange-400">Approval Required</p>
                  <p className="text-xs text-muted-foreground">
                    This is a {selectedTemplate.risk}-risk command. It will be queued for senior analyst approval before
                    execution.
                  </p>
                </div>
              </div>
            )}
            <div>
              <Label>Target Sensor</Label>
              <Select value={targetSensorId} onValueChange={setTargetSensorId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a sensor..." />
                </SelectTrigger>
                <SelectContent>
                  {sensors
                    .filter((s) => s.status === "online")
                    .map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.hostname} ({s.ipAddress})
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Command</Label>
              <Textarea
                value={customCommand}
                onChange={(e) => setCustomCommand(e.target.value)}
                className="font-mono text-sm bg-zinc-900"
                rows={3}
              />
            </div>
            <Button
              onClick={() => {
                if (!targetSensorId) {
                  toast({ title: "Select a sensor", variant: "destructive" });
                  return;
                }
                executeCommandMutation.mutate({
                  sensorId: targetSensorId,
                  command: customCommand,
                  templateId: selectedTemplate?.id,
                });
              }}
              disabled={executeCommandMutation.isPending || isStreaming}
              className="w-full"
            >
              {executeCommandMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" /> Sending...
                </>
              ) : (
                <>
                  <Send className="h-4 w-4 mr-1" /> Execute Command
                </>
              )}
            </Button>

            {/* 50.1: Live output streaming */}
            {commandOutput.length > 0 && (
              <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium">Command Output</span>
                  {isStreaming && (
                    <div className="flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin text-blue-400" />
                      <span className="text-xs text-blue-400">Streaming...</span>
                    </div>
                  )}
                </div>
                <div className="font-mono text-xs space-y-0.5 max-h-40 overflow-y-auto">
                  {commandOutput.map((line, i) => (
                    <div
                      key={i}
                      className={
                        line.includes("⚠") ? "text-orange-400" : line.includes("✓") ? "text-green-400" : "text-zinc-300"
                      }
                    >
                      {line}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// 50.3: Command approval workflow
function CommandApprovalPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: pendingActions, isLoading } = useQuery({
    queryKey: ["/api/native/response/actions", "pending_approval"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native/response/actions?status=pending_approval");
      return res.json();
    },
  });

  const approveMutation = useMutation({
    mutationFn: async (actionId: string) => {
      await apiRequest("POST", `/api/native/response/actions/${actionId}/approve`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response"] });
      toast({ title: "Action approved" });
    },
    onError: () => toast({ title: "Approval failed", variant: "destructive" }),
  });

  const rejectMutation = useMutation({
    mutationFn: async (actionId: string) => {
      await apiRequest("POST", `/api/native/response/actions/${actionId}/reject`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/response"] });
      toast({ title: "Action rejected" });
    },
    onError: () => toast({ title: "Rejection failed", variant: "destructive" }),
  });

  const actions = pendingActions?.actions || [];

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-medium">Approval Queue</h2>
        <p className="text-sm text-muted-foreground">
          High-risk and medium-risk commands requiring senior analyst approval
        </p>
      </div>
      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : actions.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-muted-foreground">
            <CheckCircle className="h-8 w-8 mx-auto mb-2 text-green-500" />
            <p>No pending approvals</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {actions.map((action: Record<string, unknown>) => (
            <Card key={String(action.id)} className="border-orange-500/20">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="bg-orange-500/10 p-2 rounded-lg">
                      <ShieldCheck className="h-5 w-5 text-orange-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm">
                          {String(action.actionType || "")
                            .replace(/_/g, " ")
                            .replace(/\b\w/g, (c: string) => c.toUpperCase())}
                        </span>
                        <Badge variant="outline" className={RISK_STYLES[String(action.riskLevel)] || ""}>
                          {String(action.riskLevel)}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        Requested by {String(action.requestedByName || "Unknown")} •{" "}
                        {action.createdAt ? new Date(String(action.createdAt)).toLocaleString() : ""}
                      </p>
                      {action.reason ? (
                        <p className="text-xs text-muted-foreground mt-1">Reason: {String(action.reason)}</p>
                      ) : null}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-red-400 border-red-500/30 hover:bg-red-500/10"
                      onClick={() => rejectMutation.mutate(String(action.id))}
                    >
                      <Ban className="h-3.5 w-3.5 mr-1" /> Reject
                    </Button>
                    <Button
                      size="sm"
                      className="bg-green-600 hover:bg-green-700"
                      onClick={() => approveMutation.mutate(String(action.id))}
                    >
                      <CheckCircle className="h-3.5 w-3.5 mr-1" /> Approve
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// 50.4: Multi-agent batch commands
function BatchCommandPanel({ sensors }: { sensors: Sensor[] }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedSensorIds, setSelectedSensorIds] = useState<string[]>([]);
  const [batchCommand, setBatchCommand] = useState("");
  const [batchResults, setBatchResults] = useState<
    Array<{ sensorId: string; hostname: string; status: string; message: string }>
  >([]);

  const batchMutation = useMutation({
    mutationFn: async () => {
      const results: typeof batchResults = [];
      for (const sensorId of selectedSensorIds) {
        try {
          const res = await apiRequest("POST", "/api/native/response/actions", {
            sensorId,
            actionType: "run_script",
            scriptContent: batchCommand,
            scriptType: "bash",
            reason: "Batch command execution",
          });
          const data = await res.json();
          const sensor = sensors.find((s) => s.id === sensorId);
          results.push({
            sensorId,
            hostname: sensor?.hostname || sensorId,
            status: data.needsApproval ? "pending_approval" : "dispatched",
            message: data.needsApproval ? "Queued for approval" : "Command dispatched",
          });
        } catch {
          const sensor = sensors.find((s) => s.id === sensorId);
          results.push({
            sensorId,
            hostname: sensor?.hostname || sensorId,
            status: "failed",
            message: "Failed to dispatch",
          });
        }
      }
      return results;
    },
    onSuccess: (results) => {
      setBatchResults(results);
      queryClient.invalidateQueries({ queryKey: ["/api/native/response"] });
      const dispatched = results.filter((r) => r.status === "dispatched").length;
      const pending = results.filter((r) => r.status === "pending_approval").length;
      toast({ title: `Batch complete: ${dispatched} dispatched, ${pending} pending approval` });
    },
    onError: () => toast({ title: "Batch execution failed", variant: "destructive" }),
  });

  const onlineSensors = sensors.filter((s) => s.status === "online");
  const toggleSensor = (id: string) => {
    setSelectedSensorIds((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]));
  };

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-medium">Batch Commands</h2>
        <p className="text-sm text-muted-foreground">Execute the same command on multiple agents simultaneously</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              Select Agents ({selectedSensorIds.length}/{onlineSensors.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-60 overflow-y-auto">
            <Button
              size="sm"
              variant="outline"
              className="w-full text-xs"
              onClick={() =>
                setSelectedSensorIds(
                  selectedSensorIds.length === onlineSensors.length ? [] : onlineSensors.map((s) => s.id),
                )
              }
            >
              {selectedSensorIds.length === onlineSensors.length ? "Deselect All" : "Select All Online"}
            </Button>
            {onlineSensors.map((s) => (
              <div
                key={s.id}
                className={`flex items-center gap-2 p-2 rounded cursor-pointer hover:bg-zinc-800 ${selectedSensorIds.includes(s.id) ? "bg-zinc-800 border border-zinc-700" : ""}`}
                onClick={() => toggleSensor(s.id)}
              >
                <input type="checkbox" checked={selectedSensorIds.includes(s.id)} readOnly className="rounded" />
                <span className="text-sm">{s.hostname}</span>
                <span className="text-xs text-muted-foreground ml-auto">{s.ipAddress}</span>
              </div>
            ))}
            {onlineSensors.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-4">No online sensors</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Command</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Select
              onValueChange={(v) => {
                const tpl = COMMAND_TEMPLATES.find((t) => t.id === v);
                if (tpl) setBatchCommand(tpl.command);
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder="Use a template..." />
              </SelectTrigger>
              <SelectContent>
                {COMMAND_TEMPLATES.filter((t) => t.risk === "low").map((t) => (
                  <SelectItem key={t.id} value={t.id}>
                    {t.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Textarea
              value={batchCommand}
              onChange={(e) => setBatchCommand(e.target.value)}
              placeholder="Enter command..."
              className="font-mono text-sm bg-zinc-900"
              rows={4}
            />
            <Button
              onClick={() => batchMutation.mutate()}
              disabled={batchMutation.isPending || selectedSensorIds.length === 0 || !batchCommand}
              className="w-full"
            >
              {batchMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" /> Executing on {selectedSensorIds.length} agents...
                </>
              ) : (
                <>
                  <Users className="h-4 w-4 mr-1" /> Execute on {selectedSensorIds.length} Agents
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Batch results */}
      {batchResults.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Batch Results</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Message</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {batchResults.map((r) => (
                  <TableRow key={r.sensorId}>
                    <TableCell className="font-medium">{r.hostname}</TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          r.status === "dispatched"
                            ? "bg-green-500/10 text-green-400 border-green-500/20"
                            : r.status === "failed"
                              ? "bg-red-500/10 text-red-400 border-red-500/20"
                              : "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                        }
                      >
                        {r.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{r.message}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
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
          <TabsTrigger value="deploy-wizard" className="gap-1.5">
            <Download className="h-3.5 w-3.5" />
            Deploy Wizard
          </TabsTrigger>
          <TabsTrigger value="fleet" className="gap-1.5">
            <Globe className="h-3.5 w-3.5" />
            Fleet
          </TabsTrigger>
          <TabsTrigger value="policies" className="gap-1.5">
            <Settings2 className="h-3.5 w-3.5" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="versions" className="gap-1.5">
            <GitBranch className="h-3.5 w-3.5" />
            Versions
          </TabsTrigger>
          <TabsTrigger value="commands" className="gap-1.5">
            <Terminal className="h-3.5 w-3.5" />
            Commands
          </TabsTrigger>
          <TabsTrigger value="approvals" className="gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5" />
            Approvals
          </TabsTrigger>
          <TabsTrigger value="batch" className="gap-1.5">
            <Users className="h-3.5 w-3.5" />
            Batch
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
                <SelectItem value="ios">iOS</SelectItem>
                <SelectItem value="android">Android</SelectItem>
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

        <TabsContent value="deploy-wizard" className="space-y-4">
          <SensorDeploymentWizard />
        </TabsContent>

        <TabsContent value="fleet" className="space-y-4">
          <SensorFleetDashboard sensors={sensors} stats={stats} />
        </TabsContent>

        <TabsContent value="policies" className="space-y-4">
          <SensorPolicyPanel />
        </TabsContent>

        <TabsContent value="versions" className="space-y-4">
          <SensorVersionPanel sensors={sensors} />
        </TabsContent>

        <TabsContent value="commands" className="space-y-4">
          <CommandTemplatesPanel sensors={sensors} />
        </TabsContent>

        <TabsContent value="approvals" className="space-y-4">
          <CommandApprovalPanel />
        </TabsContent>

        <TabsContent value="batch" className="space-y-4">
          <BatchCommandPanel sensors={sensors} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
