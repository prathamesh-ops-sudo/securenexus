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
  BarChart3,
  MonitorSmartphone,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

const STATUS_COLORS: Record<string, string> = {
  online: "bg-green-500/10 text-green-500 border-green-500/20",
  offline: "bg-red-500/10 text-red-500 border-red-500/20",
  degraded: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  provisioning: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const PLATFORM_ICONS: Record<string, string> = {
  linux: "🐧",
  windows: "🪟",
  macos: "🍎",
  docker: "🐳",
  kubernetes: "☸️",
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Native Sensors</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Lightweight agents deployed on hosts — no EDR dependency required.
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

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2">
              <MonitorSmartphone className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Total</span>
            </div>
            <p className="text-2xl font-semibold mt-1">{isLoading ? <Skeleton className="h-8 w-12" /> : stats.total}</p>
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

      {/* Filters */}
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

      {/* Sensor List */}
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
                    <span className="text-xl">{PLATFORM_ICONS[sensor.platform] || "🖥️"}</span>
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

      {/* Sensor Detail Panel */}
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
                    {(sensorDetail.recentAlerts || []).map((alert: any) => (
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
