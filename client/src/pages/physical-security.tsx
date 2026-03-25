import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  Plus,
  Search,
  AlertTriangle,
  RefreshCw,
  DoorOpen,
  MapPin,
  Clock,
  CheckCircle2,
  XCircle,
  Activity,
  Users,
  Loader2,
  Camera,
  Server,
  Building2,
  ShieldAlert,
  UserCheck,
  Wifi,
  WifiOff,
  ChevronRight,
  GitBranch,
  Zap,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { EmptyState } from "@/components/empty-state";
import { apiRequest } from "@/lib/queryClient";
import { FormPageSkeleton } from "@/components/page-skeleton";

// ── Types ─────────────────────────────────────────────────────────

interface PhysicalAsset {
  id: string;
  orgId: string;
  name: string;
  assetType: string;
  location: string;
  building: string | null;
  floor: string | null;
  zone: string | null;
  controllerType: string | null;
  controllerId: string | null;
  ipAddress: string | null;
  isOnline: boolean;
  lastHeartbeat: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

interface BadgeEvent {
  id: string;
  orgId: string;
  assetId: string | null;
  eventType: string;
  badgeNumber: string | null;
  employeeName: string | null;
  employeeEmail: string | null;
  employeeDepartment: string | null;
  location: string;
  doorName: string | null;
  direction: string | null;
  isAnomaly: boolean;
  anomalyReason: string | null;
  correlatedAlertId: string | null;
  occurredAt: string;
  createdAt: string;
}

interface PhysicalIncident {
  id: string;
  orgId: string;
  title: string;
  description: string | null;
  incidentType: string;
  severity: string;
  status: string;
  location: string | null;
  badgeEventIds: string[];
  correlatedDigitalIncidentId: string | null;
  correlatedAlertIds: string[];
  assignedTo: string | null;
  resolvedAt: string | null;
  resolutionNotes: string | null;
  createdAt: string;
  updatedAt: string;
}

interface Visitor {
  id: string;
  orgId: string;
  name: string;
  email: string | null;
  company: string | null;
  hostEmployeeName: string | null;
  hostEmployeeEmail: string | null;
  purpose: string | null;
  status: string;
  badgeNumber: string | null;
  badgeExpiry: string | null;
  scheduledAt: string | null;
  checkedInAt: string | null;
  checkedOutAt: string | null;
  areasAuthorized: string[];
  createdAt: string;
}

interface Dashboard {
  totalAssets: number;
  totalEvents24h: number;
  anomalyCount: number;
  openIncidents: number;
  activeVisitors: number;
  recentEvents: BadgeEvent[];
  // 67.1 — Facility zone status
  assetsByZone?: Array<{ zone: string; assetType: string; online: number; offline: number; total: number }>;
  // 67.2 — Recent anomalies for convergence display
  recentAnomalies?: Array<{
    id: string;
    eventType: string;
    location: string;
    badgeNumber: string | null;
    anomalyReason: string | null;
    occurredAt: string;
  }>;
  // 67.3 — Visitor stats
  visitorStats?: { total: number; preRegistered: number; checkedIn: number; checkedOut: number };
}

interface CorrelationRule {
  name: string;
  description: string;
  physicalCondition: string;
  digitalCondition: string;
  severity: string;
  windowMinutes: number;
}

// ── Helpers ───────────────────────────────────────────────────────

function severityColor(severity: string) {
  switch (severity) {
    case "critical":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "medium":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    case "low":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function statusColor(status: string) {
  switch (status) {
    case "open":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "investigating":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    case "resolved":
      return "bg-green-500/10 text-green-400 border-green-500/20";
    case "escalated":
      return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function eventTypeIcon(type: string) {
  switch (type) {
    case "access_granted":
      return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    case "access_denied":
      return <XCircle className="h-4 w-4 text-red-400" />;
    case "door_forced":
      return <ShieldAlert className="h-4 w-4 text-red-500" />;
    case "door_held":
      return <DoorOpen className="h-4 w-4 text-yellow-400" />;
    case "tailgate_detected":
      return <Users className="h-4 w-4 text-orange-400" />;
    case "antipassback_violation":
      return <AlertTriangle className="h-4 w-4 text-orange-500" />;
    case "duress_alarm":
      return <Zap className="h-4 w-4 text-red-500" />;
    case "card_unknown":
      return <XCircle className="h-4 w-4 text-zinc-400" />;
    default:
      return <Activity className="h-4 w-4 text-zinc-400" />;
  }
}

function assetTypeIcon(type: string) {
  switch (type) {
    case "access_point":
      return <DoorOpen className="h-4 w-4" />;
    case "camera":
      return <Camera className="h-4 w-4" />;
    case "server_room":
      return <Server className="h-4 w-4" />;
    case "data_center":
      return <Server className="h-4 w-4" />;
    case "office":
      return <Building2 className="h-4 w-4" />;
    default:
      return <MapPin className="h-4 w-4" />;
  }
}

function visitorStatusColor(status: string) {
  switch (status) {
    case "pre_registered":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    case "checked_in":
      return "bg-green-500/10 text-green-400 border-green-500/20";
    case "checked_out":
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
    case "denied":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "escorted":
      return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function formatDateTime(ts: string | null) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString();
}

function formatLabel(s: string) {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const ASSET_TYPES = [
  "access_point",
  "camera",
  "server_room",
  "data_center",
  "office",
  "parking_gate",
  "elevator",
  "turnstile",
  "cabinet",
  "safe",
];

const INCIDENT_TYPES = [
  "tailgate",
  "forced_entry",
  "after_hours",
  "unauthorized_access",
  "suspicious_activity",
  "equipment_tamper",
];

const CONTROLLER_TYPES = ["lenel", "genetec", "honeywell", "generic"];

// ── Main Component ────────────────────────────────────────────────

export default function PhysicalSecurityPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const { toast } = useToast();
  const qc = useQueryClient();

  // Search/filter state
  const [assetSearch, setAssetSearch] = useState("");
  const [eventSearch, setEventSearch] = useState("");
  const [visitorSearch, setVisitorSearch] = useState("");
  const [showAddAsset, setShowAddAsset] = useState(false);
  const [showAddVisitor, setShowAddVisitor] = useState(false);
  const [showAddIncident, setShowAddIncident] = useState(false);

  // Dashboard
  const { data: dashboard } = useQuery<Dashboard>({
    queryKey: ["/api/physical-security/dashboard"],
  });

  // Assets
  const { data: assetsData, isLoading: assetsLoading } = useQuery<{ items: PhysicalAsset[]; total: number }>({
    queryKey: ["/api/physical-security/assets", assetSearch],
    queryFn: () =>
      apiRequest("GET", `/api/physical-security/assets?limit=50&search=${encodeURIComponent(assetSearch)}`).then((r) =>
        r.json(),
      ),
  });

  // Badge Events
  const { data: eventsData, isLoading: eventsLoading } = useQuery<{ items: BadgeEvent[]; total: number }>({
    queryKey: ["/api/physical-security/badge-events", eventSearch],
    queryFn: () =>
      apiRequest("GET", `/api/physical-security/badge-events?limit=50&search=${encodeURIComponent(eventSearch)}`).then(
        (r) => r.json(),
      ),
  });

  // Physical Incidents
  const { data: incidentsData } = useQuery<{ items: PhysicalIncident[]; total: number }>({
    queryKey: ["/api/physical-security/incidents"],
    queryFn: () => apiRequest("GET", "/api/physical-security/incidents?limit=50").then((r) => r.json()),
  });

  // Visitors
  const { data: visitorsData } = useQuery<{ items: Visitor[]; total: number }>({
    queryKey: ["/api/physical-security/visitors", visitorSearch],
    queryFn: () =>
      apiRequest("GET", `/api/physical-security/visitors?limit=50&search=${encodeURIComponent(visitorSearch)}`).then(
        (r) => r.json(),
      ),
  });

  // Correlation Rules
  const { data: rulesData } = useQuery<{ rules: CorrelationRule[] }>({
    queryKey: ["/api/physical-security/correlation/rules"],
  });

  // Mutations
  const createAssetMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/physical-security/assets", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/physical-security/assets"] });
      qc.invalidateQueries({ queryKey: ["/api/physical-security/dashboard"] });
      setShowAddAsset(false);
      toast({ title: "Asset created" });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create asset", description: err.message, variant: "destructive" }),
  });

  const createVisitorMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/physical-security/visitors", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/physical-security/visitors"] });
      qc.invalidateQueries({ queryKey: ["/api/physical-security/dashboard"] });
      setShowAddVisitor(false);
      toast({ title: "Visitor registered" });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to register visitor", description: err.message, variant: "destructive" }),
  });

  const createIncidentMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/physical-security/incidents", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/physical-security/incidents"] });
      qc.invalidateQueries({ queryKey: ["/api/physical-security/dashboard"] });
      setShowAddIncident(false);
      toast({ title: "Incident created" });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create incident", description: err.message, variant: "destructive" }),
  });

  const runCorrelationMutation = useMutation({
    mutationFn: () =>
      apiRequest("POST", "/api/physical-security/correlation/run", { lookbackMinutes: 60 }).then((r) => r.json()),
    onSuccess: (data: { correlations: unknown[]; incidentsCreated: number }) => {
      qc.invalidateQueries({ queryKey: ["/api/physical-security/incidents"] });
      qc.invalidateQueries({ queryKey: ["/api/physical-security/dashboard"] });
      toast({
        title: `Correlation complete: ${data.correlations.length} findings, ${data.incidentsCreated} incidents created`,
      });
    },
    onError: (err: Error) => toast({ title: "Correlation failed", description: err.message, variant: "destructive" }),
  });

  const updateIncidentMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      apiRequest("PATCH", `/api/physical-security/incidents/${id}`, data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/physical-security/incidents"] });
      qc.invalidateQueries({ queryKey: ["/api/physical-security/dashboard"] });
      toast({ title: "Incident updated" });
    },
  });

  const updateVisitorMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      apiRequest("PATCH", `/api/physical-security/visitors/${id}`, data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/physical-security/visitors"] });
      qc.invalidateQueries({ queryKey: ["/api/physical-security/dashboard"] });
      toast({ title: "Visitor updated" });
    },
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Physical Security Convergence</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Badge access integration, anomaly correlation, visitor management, and CCTV monitoring
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => runCorrelationMutation.mutate()}
            disabled={runCorrelationMutation.isPending}
          >
            {runCorrelationMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <GitBranch className="h-4 w-4 mr-1" />
            )}
            Run Correlation
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="assets">Assets</TabsTrigger>
          <TabsTrigger value="events">Badge Events</TabsTrigger>
          <TabsTrigger value="incidents">Incidents</TabsTrigger>
          <TabsTrigger value="visitors">Visitors</TabsTrigger>
          <TabsTrigger value="correlation">Correlation</TabsTrigger>
        </TabsList>

        {/* ── Overview ─────────────────────────────────────────── */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Physical Assets</p>
                    <p className="text-2xl font-bold">{dashboard?.totalAssets ?? 0}</p>
                  </div>
                  <Server className="h-8 w-8 text-blue-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Events (24h)</p>
                    <p className="text-2xl font-bold">{dashboard?.totalEvents24h ?? 0}</p>
                  </div>
                  <Activity className="h-8 w-8 text-green-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Anomalies (24h)</p>
                    <p className="text-2xl font-bold">{dashboard?.anomalyCount ?? 0}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-orange-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Open Incidents</p>
                    <p className="text-2xl font-bold">{dashboard?.openIncidents ?? 0}</p>
                  </div>
                  <ShieldAlert className="h-8 w-8 text-red-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Active Visitors</p>
                    <p className="text-2xl font-bold">{dashboard?.activeVisitors ?? 0}</p>
                  </div>
                  <UserCheck className="h-8 w-8 text-purple-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* 67.1 — Facility Floor Plan Status (zone-level asset summary) */}
          {dashboard?.assetsByZone && dashboard.assetsByZone.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Facility Zone Status</CardTitle>
                <CardDescription>Real-time asset status by zone and type</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {dashboard.assetsByZone.map(
                    (
                      z: { zone: string; assetType: string; online: number; offline: number; total: number },
                      i: number,
                    ) => (
                      <div key={i} className="p-3 border border-border/50 rounded-lg">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium">{z.zone || "Unzoned"}</span>
                          <Badge variant="outline" className="text-[10px]">
                            {formatLabel(z.assetType)}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-3 text-xs">
                          <span className="text-green-500">{z.online} online</span>
                          <span className="text-red-400">{z.offline} offline</span>
                          <span className="text-muted-foreground">{z.total} total</span>
                        </div>
                        <div className="mt-1.5 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-green-500 rounded-full"
                            style={{ width: `${z.total > 0 ? (z.online / z.total) * 100 : 0}%` }}
                          />
                        </div>
                      </div>
                    ),
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 67.4 — Physical-Cyber Convergence (recent anomalies) */}
          {dashboard?.recentAnomalies && dashboard.recentAnomalies.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Physical-Cyber Convergence Events</CardTitle>
                <CardDescription>Anomalous badge events correlated with digital security alerts</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {dashboard.recentAnomalies.map(
                    (a: {
                      id: string;
                      eventType: string;
                      location: string;
                      badgeNumber: string | null;
                      anomalyReason: string | null;
                      occurredAt: string;
                    }) => (
                      <div
                        key={a.id}
                        className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                      >
                        <div className="flex items-center gap-3">
                          <AlertTriangle className="h-4 w-4 text-orange-400" />
                          <div>
                            <p className="text-sm font-medium">
                              {formatLabel(a.eventType)} at {a.location}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              {a.anomalyReason || "Anomalous event detected"}
                            </p>
                          </div>
                        </div>
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatDateTime(a.occurredAt)}
                        </span>
                      </div>
                    ),
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 67.3 — Visitor Stats */}
          {dashboard?.visitorStats && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Visitor Management Summary</CardTitle>
                <CardDescription>Current visitor check-in status and pre-registration overview</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <p className="text-2xl font-bold">{dashboard.visitorStats.total}</p>
                    <p className="text-xs text-muted-foreground">Total Visitors</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-blue-400">{dashboard.visitorStats.preRegistered}</p>
                    <p className="text-xs text-muted-foreground">Pre-Registered</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-green-400">{dashboard.visitorStats.checkedIn}</p>
                    <p className="text-xs text-muted-foreground">Checked In</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-muted-foreground">{dashboard.visitorStats.checkedOut}</p>
                    <p className="text-xs text-muted-foreground">Checked Out</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Recent Events */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Recent Badge Events</CardTitle>
              <CardDescription>Last 24 hours of badge activity</CardDescription>
            </CardHeader>
            <CardContent>
              {(dashboard?.recentEvents ?? []).length === 0 ? (
                <EmptyState
                  icon={DoorOpen}
                  title="No badge events in the last 24 hours"
                  description="Connect a physical access control system (badge readers, turnstiles) to start monitoring entry/exit events and detecting anomalous access patterns."
                  compact
                />
              ) : (
                <div className="space-y-2">
                  {dashboard?.recentEvents.map((event) => (
                    <div
                      key={event.id}
                      className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                    >
                      <div className="flex items-center gap-3">
                        {eventTypeIcon(event.eventType)}
                        <div>
                          <p className="text-sm font-medium">{event.employeeName || event.badgeNumber || "Unknown"}</p>
                          <p className="text-xs text-muted-foreground">
                            {formatLabel(event.eventType)} at {event.location}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {event.isAnomaly && (
                          <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 text-xs">
                            Anomaly
                          </Badge>
                        )}
                        {/* 67.5 — Camera feed indicator */}
                        <Camera className="h-3 w-3 text-muted-foreground opacity-50" />
                        <span className="text-xs text-muted-foreground">{formatDateTime(event.occurredAt)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Assets ───────────────────────────────────────────── */}
        <TabsContent value="assets" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search assets..."
                value={assetSearch}
                onChange={(e) => setAssetSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Dialog open={showAddAsset} onOpenChange={setShowAddAsset}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Add Asset
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add Physical Asset</DialogTitle>
                  <DialogDescription>
                    Register a new physical security asset (access point, camera, server room, etc.)
                  </DialogDescription>
                </DialogHeader>
                <AddAssetForm
                  onSubmit={(data) => createAssetMutation.mutate(data)}
                  isPending={createAssetMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>

          {assetsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : (assetsData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent>
                <EmptyState
                  icon={Shield}
                  title="No physical assets registered"
                  description="Register access points, cameras, server rooms, and other physical security assets to enable convergence with cyber security events."
                  action={{
                    label: "Add Asset",
                    icon: Plus,
                    onClick: () => setShowAddAsset(true),
                  }}
                />
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {assetsData?.items.map((asset) => (
                <Card key={asset.id}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        {assetTypeIcon(asset.assetType)}
                        <div>
                          <p className="text-sm font-medium">{asset.name}</p>
                          <p className="text-xs text-muted-foreground">{formatLabel(asset.assetType)}</p>
                        </div>
                      </div>
                      {asset.isOnline ? (
                        <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/20 text-xs">
                          <Wifi className="h-3 w-3 mr-1" /> Online
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 text-xs">
                          <WifiOff className="h-3 w-3 mr-1" /> Offline
                        </Badge>
                      )}
                    </div>
                    <div className="mt-3 space-y-1">
                      <p className="text-xs text-muted-foreground">
                        <MapPin className="h-3 w-3 inline mr-1" />
                        {asset.location}
                      </p>
                      {asset.building && (
                        <p className="text-xs text-muted-foreground">
                          <Building2 className="h-3 w-3 inline mr-1" />
                          {asset.building}
                          {asset.floor ? `, Floor ${asset.floor}` : ""}
                        </p>
                      )}
                      {asset.controllerType && (
                        <p className="text-xs text-muted-foreground">
                          <Shield className="h-3 w-3 inline mr-1" />
                          {formatLabel(asset.controllerType)}
                        </p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Badge Events ─────────────────────────────────────── */}
        <TabsContent value="events" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by name, badge number, or location..."
                value={eventSearch}
                onChange={(e) => setEventSearch(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>

          {eventsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : (eventsData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent>
                <EmptyState
                  icon={DoorOpen}
                  title="No badge events recorded"
                  description="Badge events appear as physical access control systems report swipe, tap, and tailgating activity. Connect a badge system from the Connectors page."
                />
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="pt-6">
                <div className="space-y-2">
                  {eventsData?.items.map((event) => (
                    <div
                      key={event.id}
                      className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                    >
                      <div className="flex items-center gap-3">
                        {eventTypeIcon(event.eventType)}
                        <div>
                          <p className="text-sm font-medium">{event.employeeName || event.badgeNumber || "Unknown"}</p>
                          <p className="text-xs text-muted-foreground">
                            {formatLabel(event.eventType)} {event.doorName ? `at ${event.doorName}` : ""} —{" "}
                            {event.location}
                          </p>
                          {event.employeeDepartment && (
                            <p className="text-xs text-muted-foreground">Dept: {event.employeeDepartment}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {event.direction && (
                          <Badge variant="outline" className="text-xs">
                            {event.direction}
                          </Badge>
                        )}
                        {event.isAnomaly && (
                          <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 text-xs">
                            <AlertTriangle className="h-3 w-3 mr-1" /> Anomaly
                          </Badge>
                        )}
                        {/* 67.2 — Anomaly reason display */}
                        {event.isAnomaly && event.anomalyReason && (
                          <span
                            className="text-[10px] text-orange-400 max-w-[200px] truncate"
                            title={event.anomalyReason}
                          >
                            {event.anomalyReason}
                          </span>
                        )}
                        {/* 67.5 — Camera indicator */}
                        <Camera className="h-3 w-3 text-muted-foreground opacity-40" />
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatDateTime(event.occurredAt)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Incidents ────────────────────────────────────────── */}
        <TabsContent value="incidents" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">{incidentsData?.total ?? 0} physical incident(s)</p>
            <Dialog open={showAddIncident} onOpenChange={setShowAddIncident}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Create Incident
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Physical Incident</DialogTitle>
                  <DialogDescription>Report a physical security incident for investigation</DialogDescription>
                </DialogHeader>
                <AddIncidentForm
                  onSubmit={(data) => createIncidentMutation.mutate(data)}
                  isPending={createIncidentMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>

          {(incidentsData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent>
                <EmptyState
                  icon={ShieldAlert}
                  title="No physical incidents"
                  description="Physical incidents are created manually or automatically by the correlation engine when anomalous badge patterns are detected (e.g., tailgating, after-hours access)."
                  action={{
                    label: "Create Incident",
                    icon: Plus,
                    onClick: () => setShowAddIncident(true),
                  }}
                />
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {incidentsData?.items.map((incident) => (
                <Card key={incident.id}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="h-4 w-4 text-red-400" />
                          <p className="text-sm font-medium">{incident.title}</p>
                        </div>
                        {incident.description && (
                          <p className="text-xs text-muted-foreground mt-1">{incident.description}</p>
                        )}
                        <div className="flex items-center gap-2 mt-2">
                          <Badge variant="outline" className={`${severityColor(incident.severity)} text-xs`}>
                            {incident.severity}
                          </Badge>
                          <Badge variant="outline" className={`${statusColor(incident.status)} text-xs`}>
                            {formatLabel(incident.status)}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{formatLabel(incident.incidentType)}</span>
                          {incident.location && (
                            <span className="text-xs text-muted-foreground">
                              <MapPin className="h-3 w-3 inline mr-1" />
                              {incident.location}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex gap-1">
                        {incident.status !== "resolved" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => updateIncidentMutation.mutate({ id: incident.id, status: "resolved" })}
                          >
                            Resolve
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Visitors ─────────────────────────────────────────── */}
        <TabsContent value="visitors" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search visitors..."
                value={visitorSearch}
                onChange={(e) => setVisitorSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Dialog open={showAddVisitor} onOpenChange={setShowAddVisitor}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Register Visitor
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Register Visitor</DialogTitle>
                  <DialogDescription>Pre-register a visitor for physical access tracking</DialogDescription>
                </DialogHeader>
                <AddVisitorForm
                  onSubmit={(data) => createVisitorMutation.mutate(data)}
                  isPending={createVisitorMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>

          {(visitorsData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent>
                <EmptyState
                  icon={UserCheck}
                  title="No visitors registered"
                  description="Pre-register visitors to track physical access, assign temporary badges, and correlate visitor presence with digital security events."
                  action={{
                    label: "Register Visitor",
                    icon: Plus,
                    onClick: () => setShowAddVisitor(true),
                  }}
                />
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {visitorsData?.items.map((visitor) => (
                <Card key={visitor.id}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-sm font-medium">{visitor.name}</p>
                        <div className="flex items-center gap-2 mt-1">
                          {visitor.company && <span className="text-xs text-muted-foreground">{visitor.company}</span>}
                          {visitor.hostEmployeeName && (
                            <span className="text-xs text-muted-foreground">Host: {visitor.hostEmployeeName}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                          <Badge variant="outline" className={`${visitorStatusColor(visitor.status)} text-xs`}>
                            {formatLabel(visitor.status)}
                          </Badge>
                          {visitor.purpose && <span className="text-xs text-muted-foreground">{visitor.purpose}</span>}
                        </div>
                        {/* 67.3 — Temporary badge display */}
                        {visitor.badgeNumber && (
                          <p className="text-xs text-muted-foreground mt-1">
                            <Shield className="h-3 w-3 inline mr-1" />
                            Badge: {visitor.badgeNumber}
                            {visitor.badgeExpiry && (
                              <span className="ml-1 text-yellow-500">
                                (expires {formatDateTime(visitor.badgeExpiry)})
                              </span>
                            )}
                          </p>
                        )}
                      </div>
                      <div className="flex gap-1">
                        {visitor.status === "pre_registered" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => updateVisitorMutation.mutate({ id: visitor.id, status: "checked_in" })}
                          >
                            Check In
                          </Button>
                        )}
                        {visitor.status === "checked_in" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => updateVisitorMutation.mutate({ id: visitor.id, status: "checked_out" })}
                          >
                            Check Out
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Correlation Rules ────────────────────────────────── */}
        <TabsContent value="correlation" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Anomaly Correlation Rules</CardTitle>
              <CardDescription>
                Built-in rules that correlate physical badge events with digital security alerts. Run correlation
                manually or configure automatic scheduling.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(rulesData?.rules ?? []).map((rule, i) => (
                  <div key={i} className="p-3 border border-border/50 rounded-lg">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-sm font-medium">{rule.name}</p>
                        <p className="text-xs text-muted-foreground mt-1">{rule.description}</p>
                      </div>
                      <Badge variant="outline" className={`${severityColor(rule.severity)} text-xs`}>
                        {rule.severity}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 mt-2">
                      <span className="text-xs text-muted-foreground">
                        <Shield className="h-3 w-3 inline mr-1" />
                        Physical: {formatLabel(rule.physicalCondition)}
                      </span>
                      <ChevronRight className="h-3 w-3 text-muted-foreground" />
                      <span className="text-xs text-muted-foreground">
                        <Activity className="h-3 w-3 inline mr-1" />
                        Digital: {formatLabel(rule.digitalCondition)}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        <Clock className="h-3 w-3 inline mr-1" />
                        Window: {rule.windowMinutes}m
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Controller Integrations</CardTitle>
              <CardDescription>
                Connect to physical access control systems (Lenel OnGuard, Genetec Security Center, Honeywell Pro-Watch)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  {
                    name: "Lenel OnGuard",
                    type: "lenel",
                    desc: "Lenel REST API integration for badge events and cardholder management",
                  },
                  {
                    name: "Genetec Security Center",
                    type: "genetec",
                    desc: "Genetec Security Center SDK for unified physical security",
                  },
                  {
                    name: "Honeywell Pro-Watch",
                    type: "honeywell",
                    desc: "Honeywell Pro-Watch integration for access control and alarm monitoring",
                  },
                ].map((ctrl) => (
                  <div key={ctrl.type} className="p-4 border border-border/50 rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="h-5 w-5 text-blue-400" />
                      <p className="text-sm font-medium">{ctrl.name}</p>
                    </div>
                    <p className="text-xs text-muted-foreground mb-3">{ctrl.desc}</p>
                    <Button variant="outline" size="sm" className="w-full" disabled>
                      Configure
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Forms ──────────────────────────────────────────────────────────

function AddAssetForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState("");
  const [assetType, setAssetType] = useState("access_point");
  const [location, setLocation] = useState("");
  const [building, setBuilding] = useState("");
  const [floor, setFloor] = useState("");
  const [controllerType, setControllerType] = useState("");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Name *</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Main Entrance Reader" />
      </div>
      <div className="space-y-2">
        <Label>Asset Type *</Label>
        <Select value={assetType} onValueChange={setAssetType}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ASSET_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {formatLabel(t)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-2">
        <Label>Location *</Label>
        <Input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="Building A, Floor 1" />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Building</Label>
          <Input value={building} onChange={(e) => setBuilding(e.target.value)} placeholder="Building A" />
        </div>
        <div className="space-y-2">
          <Label>Floor</Label>
          <Input value={floor} onChange={(e) => setFloor(e.target.value)} placeholder="1" />
        </div>
      </div>
      <div className="space-y-2">
        <Label>Controller Type</Label>
        <Select value={controllerType} onValueChange={setControllerType}>
          <SelectTrigger>
            <SelectValue placeholder="Select controller..." />
          </SelectTrigger>
          <SelectContent>
            {CONTROLLER_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {formatLabel(t)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              name,
              assetType,
              location,
              building: building || undefined,
              floor: floor || undefined,
              controllerType: controllerType || undefined,
            })
          }
          disabled={!name || !location || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
          Add Asset
        </Button>
      </DialogFooter>
    </div>
  );
}

function AddIncidentForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [incidentType, setIncidentType] = useState("unauthorized_access");
  const [severity, setSeverity] = useState("medium");
  const [location, setLocation] = useState("");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Title *</Label>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Unauthorized access attempt" />
      </div>
      <div className="space-y-2">
        <Label>Description</Label>
        <Textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Describe the incident..."
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Type *</Label>
          <Select value={incidentType} onValueChange={setIncidentType}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {INCIDENT_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {formatLabel(t)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Severity</Label>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["critical", "high", "medium", "low"].map((s) => (
                <SelectItem key={s} value={s}>
                  {formatLabel(s)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-2">
        <Label>Location</Label>
        <Input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="Building A, Floor 2" />
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              title,
              description: description || undefined,
              incidentType,
              severity,
              location: location || undefined,
            })
          }
          disabled={!title || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
          Create Incident
        </Button>
      </DialogFooter>
    </div>
  );
}

function AddVisitorForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [hostName, setHostName] = useState("");
  const [purpose, setPurpose] = useState("");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Visitor Name *</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="John Smith" />
      </div>
      <div className="space-y-2">
        <Label>Email</Label>
        <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="john@example.com" />
      </div>
      <div className="space-y-2">
        <Label>Company</Label>
        <Input value={company} onChange={(e) => setCompany(e.target.value)} placeholder="Acme Corp" />
      </div>
      <div className="space-y-2">
        <Label>Host Employee</Label>
        <Input value={hostName} onChange={(e) => setHostName(e.target.value)} placeholder="Jane Doe" />
      </div>
      <div className="space-y-2">
        <Label>Purpose of Visit</Label>
        <Input value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="Business meeting" />
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              name,
              email: email || undefined,
              company: company || undefined,
              hostEmployeeName: hostName || undefined,
              purpose: purpose || undefined,
            })
          }
          disabled={!name || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
          Register Visitor
        </Button>
      </DialogFooter>
    </div>
  );
}
