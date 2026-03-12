import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  Server,
  AlertTriangle,
  Plus,
  Activity,
  Network,
  Cpu,
  Radio,
  Factory,
  Gauge,
  ShieldAlert,
  Layers,
  ArrowUpDown,
  FileWarning,
  ExternalLink,
  Zap,
  Eye,
  CheckCircle,
  XCircle,
  Clock,
  BarChart3,
  BookOpen,
} from "lucide-react";

// =========================================================================
// TYPES
// =========================================================================

interface OtAsset {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  assetType: string;
  ipAddress: string | null;
  macAddress: string | null;
  hostname: string | null;
  purdueLevel: string | null;
  zone: string | null;
  vendor: string | null;
  model: string | null;
  firmwareVersion: string | null;
  serialNumber: string | null;
  protocols: string[] | null;
  facility: string | null;
  area: string | null;
  line: string | null;
  status: string;
  lastSeen: string | null;
  firstSeen: string | null;
  isCritical: boolean;
  isSafetySystem: boolean;
  silRating: string | null;
  cveCount: number;
  highestCvss: number | null;
  tags: string[] | null;
  discoveredBy: string | null;
  createdAt: string;
  updatedAt: string;
}

interface OtConnection {
  id: string;
  sourceAssetId: string | null;
  destAssetId: string | null;
  sourceIp: string | null;
  destIp: string | null;
  sourcePort: number | null;
  destPort: number | null;
  protocol: string | null;
  sourcePurdueLevel: string | null;
  destPurdueLevel: string | null;
  crossesBoundary: boolean;
  isAllowed: boolean;
  packetCount: number;
  byteCount: number;
  lastActivity: string | null;
}

interface OtAnomaly {
  id: string;
  assetId: string | null;
  anomalyType: string;
  severity: string;
  title: string;
  description: string | null;
  protocol: string | null;
  functionCode: number | null;
  sourceIp: string | null;
  destIp: string | null;
  icsCertAdvisory: string | null;
  mitreTactic: string | null;
  mitreTechnique: string | null;
  status: string;
  detectedAt: string;
}

interface IcsCertAdvisory {
  id: string;
  title: string;
  vendor: string;
  product: string;
  severity: string;
  cvss: number;
  cveIds: string[];
  description: string;
  affectedVersions: string;
  mitigation: string;
  publishedAt: string;
  url: string;
}

interface ThreatSignature {
  id: string;
  name: string;
  description: string;
  protocol: string;
  severity: string;
  mitreTactic: string;
  mitreTechnique: string;
  icsCertAdvisory: string | null;
}

interface TopologyData {
  levels: Array<{
    level: string;
    levelName: string;
    description: string;
    assets: OtAsset[];
    assetCount: number;
  }>;
  connections: OtConnection[];
  boundaryCrossings: OtConnection[];
  totalAssets: number;
  totalConnections: number;
  boundaryCrossingCount: number;
}

interface OtStats {
  totalAssets: number;
  criticalAssets: number;
  safetySystems: number;
  totalConnections: number;
  boundaryCrossings: number;
  openAnomalies: number;
  criticalAnomalies: number;
  assetsByType: Array<{ assetType: string; count: number }>;
  assetsByLevel: Array<{ purdueLevel: string | null; count: number }>;
  anomaliesBySeverity: Array<{ severity: string; count: number }>;
  protocolDistribution: Array<{ protocol: string; count: number }>;
}

// =========================================================================
// CONSTANTS
// =========================================================================

const ASSET_TYPE_LABELS: Record<string, { label: string; icon: typeof Cpu }> = {
  plc: { label: "PLC", icon: Cpu },
  hmi: { label: "HMI", icon: Gauge },
  scada_server: { label: "SCADA Server", icon: Server },
  rtu: { label: "RTU", icon: Radio },
  dcs: { label: "DCS", icon: Factory },
  engineering_workstation: { label: "Eng. Workstation", icon: Cpu },
  historian: { label: "Historian", icon: BarChart3 },
  safety_system: { label: "Safety System", icon: ShieldAlert },
  network_switch: { label: "Network Switch", icon: Network },
  firewall: { label: "Firewall", icon: Shield },
  gateway: { label: "Gateway", icon: ArrowUpDown },
  sensor: { label: "Sensor", icon: Activity },
  actuator: { label: "Actuator", icon: Zap },
  drive: { label: "Drive", icon: Cpu },
  robot: { label: "Robot", icon: Factory },
  meter: { label: "Meter", icon: Gauge },
  relay: { label: "Relay", icon: Radio },
  other: { label: "Other", icon: Server },
};

const PURDUE_LEVEL_LABELS: Record<string, { label: string; color: string; bgColor: string }> = {
  level_0: { label: "L0 — Physical Process", color: "text-red-400", bgColor: "bg-red-950/40 border-red-800/30" },
  level_1: { label: "L1 — Basic Control", color: "text-orange-400", bgColor: "bg-orange-950/40 border-orange-800/30" },
  level_2: { label: "L2 — Area Supervisory", color: "text-amber-400", bgColor: "bg-amber-950/40 border-amber-800/30" },
  level_3: {
    label: "L3 — Site Operations",
    color: "text-yellow-400",
    bgColor: "bg-yellow-950/40 border-yellow-800/30",
  },
  level_3_5: { label: "L3.5 — IT/OT DMZ", color: "text-cyan-400", bgColor: "bg-cyan-950/40 border-cyan-800/30" },
  level_4: { label: "L4 — Enterprise IT", color: "text-blue-400", bgColor: "bg-blue-950/40 border-blue-800/30" },
  level_5: {
    label: "L5 — Enterprise / Internet",
    color: "text-purple-400",
    bgColor: "bg-purple-950/40 border-purple-800/30",
  },
};

const ANOMALY_TYPE_LABELS: Record<string, string> = {
  unauthorized_access: "Unauthorized Access",
  firmware_change: "Firmware Change",
  configuration_change: "Configuration Change",
  ladder_logic_modification: "Ladder Logic Modification",
  setpoint_change: "Setpoint Change",
  network_scan: "Network Scan",
  new_device: "New Device Detected",
  protocol_violation: "Protocol Violation",
  it_ot_boundary_crossing: "IT/OT Boundary Crossing",
  safety_system_bypass: "Safety System Bypass",
  hmi_anomaly: "HMI Anomaly",
  denial_of_service: "Denial of Service",
  replay_attack: "Replay Attack",
  man_in_the_middle: "Man-in-the-Middle",
  plc_stop_command: "PLC Stop Command",
  plc_mode_change: "PLC Mode Change",
  unexpected_write: "Unexpected Write",
  process_value_anomaly: "Process Value Anomaly",
  communication_loss: "Communication Loss",
  unknown: "Unknown",
};

const PROTOCOL_LABELS: Record<string, string> = {
  modbus_tcp: "Modbus TCP",
  modbus_rtu: "Modbus RTU",
  dnp3: "DNP3",
  opc_ua: "OPC-UA",
  opc_da: "OPC-DA",
  ethernet_ip: "EtherNet/IP",
  profinet: "Profinet",
  bacnet: "BACnet",
  iec_61850: "IEC 61850",
  iec_104: "IEC 104",
  s7comm: "S7comm",
  fins: "FINS",
  hart: "HART",
  mqtt: "MQTT",
  coap: "CoAP",
  unknown: "Unknown",
};

// =========================================================================
// API HELPER
// =========================================================================

async function apiRequest(url: string, options?: RequestInit) {
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }));
    const msg = body?.errors?.[0]?.message || body.message || res.statusText;
    throw new Error(msg);
  }
  const json = await res.json();
  // Unwrap envelope middleware { data, meta, errors } shape
  if (json && typeof json === "object" && "data" in json && "meta" in json) {
    return json.data;
  }
  return json;
}

// =========================================================================
// MAIN PAGE
// =========================================================================

export default function OtSecurityPage() {
  const [activeTab, setActiveTab] = useState("overview");

  const { data: stats } = useQuery<OtStats>({
    queryKey: ["/api/ot/stats"],
    queryFn: () => apiRequest("/api/ot/stats"),
  });

  const { data: topology } = useQuery<TopologyData>({
    queryKey: ["/api/ot/topology"],
    queryFn: () => apiRequest("/api/ot/topology"),
  });

  const { data: assets } = useQuery<OtAsset[]>({
    queryKey: ["/api/ot/assets"],
    queryFn: () => apiRequest("/api/ot/assets"),
  });

  const { data: anomalies } = useQuery<OtAnomaly[]>({
    queryKey: ["/api/ot/anomalies"],
    queryFn: () => apiRequest("/api/ot/anomalies"),
  });

  const { data: advisories } = useQuery<IcsCertAdvisory[]>({
    queryKey: ["/api/ot/advisories"],
    queryFn: () => apiRequest("/api/ot/advisories"),
  });

  const { data: signatures } = useQuery<ThreatSignature[]>({
    queryKey: ["/api/ot/signatures"],
    queryFn: () => apiRequest("/api/ot/signatures"),
  });

  const { data: boundary } = useQuery({
    queryKey: ["/api/ot/boundary"],
    queryFn: () => apiRequest("/api/ot/boundary"),
  });

  return (
    <div className="flex-1 space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">OT/ICS Security</h1>
          <p className="text-muted-foreground">
            Industrial control system monitoring — passive asset discovery, protocol analysis, Purdue Model topology
          </p>
        </div>
        <div className="flex items-center gap-2">
          <CreateAssetDialog />
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="topology">Purdue Model</TabsTrigger>
          <TabsTrigger value="assets">Assets</TabsTrigger>
          <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
          <TabsTrigger value="boundary">IT/OT Boundary</TabsTrigger>
          <TabsTrigger value="signatures">Threat Signatures</TabsTrigger>
          <TabsTrigger value="advisories">ICS-CERT</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <StatsCards stats={stats} />
          <div className="grid grid-cols-1 gap-6 mt-6 lg:grid-cols-2">
            <RecentAnomaliesCard anomalies={anomalies} />
            <ProtocolDistributionCard stats={stats} />
          </div>
        </TabsContent>

        <TabsContent value="topology">
          <PurdueModelView topology={topology} />
        </TabsContent>

        <TabsContent value="assets">
          <AssetInventory assets={assets} />
        </TabsContent>

        <TabsContent value="anomalies">
          <AnomalyDashboard anomalies={anomalies} />
        </TabsContent>

        <TabsContent value="boundary">
          <BoundaryMonitor boundary={boundary} />
        </TabsContent>

        <TabsContent value="signatures">
          <ThreatSignatures signatures={signatures} />
        </TabsContent>

        <TabsContent value="advisories">
          <IcsCertAdvisories advisories={advisories} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// =========================================================================
// STATS CARDS
// =========================================================================

function StatsCards({ stats }: { stats?: OtStats }) {
  const cards = [
    {
      title: "OT Assets",
      value: stats?.totalAssets ?? 0,
      description: `${stats?.criticalAssets ?? 0} critical`,
      icon: Cpu,
      color: "text-blue-400",
    },
    {
      title: "Safety Systems",
      value: stats?.safetySystems ?? 0,
      description: "SIS/SIL monitored",
      icon: ShieldAlert,
      color: "text-amber-400",
    },
    {
      title: "Connections",
      value: stats?.totalConnections ?? 0,
      description: `${stats?.boundaryCrossings ?? 0} boundary crossings`,
      icon: Network,
      color: "text-cyan-400",
    },
    {
      title: "Open Anomalies",
      value: stats?.openAnomalies ?? 0,
      description: `${stats?.criticalAnomalies ?? 0} critical`,
      icon: AlertTriangle,
      color: stats?.criticalAnomalies ? "text-red-400" : "text-green-400",
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {cards.map((card) => (
        <Card key={card.title}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">{card.title}</CardTitle>
            <card.icon className={`h-4 w-4 ${card.color}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{card.value}</div>
            <p className="text-xs text-muted-foreground">{card.description}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// =========================================================================
// RECENT ANOMALIES CARD
// =========================================================================

function RecentAnomaliesCard({ anomalies }: { anomalies?: OtAnomaly[] }) {
  const recent = (anomalies || []).slice(0, 8);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Recent Anomalies</CardTitle>
        <CardDescription>Latest OT/ICS security events</CardDescription>
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <CheckCircle className="h-10 w-10 text-green-500 mb-2" />
            <p className="text-sm text-muted-foreground">No anomalies detected</p>
            <p className="text-xs text-muted-foreground mt-1">OT network is operating normally</p>
          </div>
        ) : (
          <div className="space-y-3">
            {recent.map((a) => (
              <div key={a.id} className="flex items-start gap-3 rounded-lg border p-3">
                <SeverityBadge severity={a.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{a.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {ANOMALY_TYPE_LABELS[a.anomalyType] || a.anomalyType}
                    {a.protocol ? ` · ${PROTOCOL_LABELS[a.protocol] || a.protocol}` : ""}
                  </p>
                </div>
                <span className="text-xs text-muted-foreground whitespace-nowrap">
                  {new Date(a.detectedAt).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// =========================================================================
// PROTOCOL DISTRIBUTION CARD
// =========================================================================

function ProtocolDistributionCard({ stats }: { stats?: OtStats }) {
  const protocols = stats?.protocolDistribution || [];
  const total = protocols.reduce((sum, p) => sum + p.count, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Protocol Distribution</CardTitle>
        <CardDescription>Industrial protocol event breakdown</CardDescription>
      </CardHeader>
      <CardContent>
        {protocols.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <Radio className="h-10 w-10 text-muted-foreground mb-2" />
            <p className="text-sm text-muted-foreground">No protocol events captured</p>
            <p className="text-xs text-muted-foreground mt-1">Deploy an OT sensor to start capturing traffic</p>
          </div>
        ) : (
          <div className="space-y-3">
            {protocols.map((p) => {
              const pct = total > 0 ? ((p.count / total) * 100).toFixed(1) : "0";
              return (
                <div key={p.protocol} className="flex items-center gap-3">
                  <span className="text-sm font-mono w-24 truncate">{PROTOCOL_LABELS[p.protocol] || p.protocol}</span>
                  <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                    <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xs text-muted-foreground w-16 text-right">
                    {p.count.toLocaleString()} ({pct}%)
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// =========================================================================
// PURDUE MODEL VIEW
// =========================================================================

function PurdueModelView({ topology }: { topology?: TopologyData }) {
  if (!topology) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <p className="text-muted-foreground">Loading topology...</p>
        </CardContent>
      </Card>
    );
  }

  const levels = topology.levels;
  // Reverse so Level 5 is at top, Level 0 at bottom (standard Purdue diagram)
  const sortedLevels = [...levels].sort((a, b) => {
    const order: Record<string, number> = {
      level_5: 6,
      level_4: 5,
      level_3_5: 4,
      level_3: 3,
      level_2: 2,
      level_1: 1,
      level_0: 0,
    };
    return (order[b.level] ?? 0) - (order[a.level] ?? 0);
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Purdue Model Network Segmentation</h2>
          <p className="text-sm text-muted-foreground">
            {topology.totalAssets} assets · {topology.totalConnections} connections · {topology.boundaryCrossingCount}{" "}
            boundary crossings
          </p>
        </div>
      </div>

      <div className="space-y-2">
        {sortedLevels.map((level) => {
          const levelInfo = PURDUE_LEVEL_LABELS[level.level];
          const isDmz = level.level === "level_3_5";

          return (
            <div
              key={level.level}
              className={`rounded-lg border p-4 ${levelInfo?.bgColor || "bg-muted/30 border-border"}`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Layers className={`h-4 w-4 ${levelInfo?.color || "text-muted-foreground"}`} />
                  <span className={`text-sm font-semibold ${levelInfo?.color || ""}`}>
                    {levelInfo?.label || level.levelName}
                  </span>
                  {isDmz ? (
                    <Badge variant="outline" className="text-xs border-cyan-700 text-cyan-400">
                      AIR GAP
                    </Badge>
                  ) : null}
                </div>
                <span className="text-xs text-muted-foreground">
                  {level.assetCount} asset{level.assetCount !== 1 ? "s" : ""}
                </span>
              </div>

              <p className="text-xs text-muted-foreground mb-3">{level.description}</p>

              {level.assets.length > 0 ? (
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
                  {level.assets.map((asset) => {
                    const typeInfo = ASSET_TYPE_LABELS[asset.assetType];
                    const Icon = typeInfo?.icon || Server;
                    return (
                      <div key={asset.id} className="flex items-center gap-2 rounded border bg-background/60 p-2">
                        <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <div className="min-w-0 flex-1">
                          <p className="text-xs font-medium truncate">{asset.name}</p>
                          <p className="text-[10px] text-muted-foreground truncate">
                            {typeInfo?.label || asset.assetType}
                            {asset.ipAddress ? ` · ${asset.ipAddress}` : ""}
                          </p>
                        </div>
                        {asset.isCritical ? <AlertTriangle className="h-3 w-3 text-red-400 shrink-0" /> : null}
                        {asset.isSafetySystem ? <ShieldAlert className="h-3 w-3 text-amber-400 shrink-0" /> : null}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground italic">No assets at this level</p>
              )}
            </div>
          );
        })}
      </div>

      {topology.boundaryCrossingCount > 0 ? (
        <Card className="border-red-800/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-red-400 flex items-center gap-2">
              <ArrowUpDown className="h-4 w-4" />
              IT/OT Boundary Crossings ({topology.boundaryCrossingCount})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {topology.boundaryCrossings.slice(0, 10).map((c) => (
                <div key={c.id} className="flex items-center gap-3 text-xs">
                  <Badge variant={c.isAllowed ? "secondary" : "destructive"} className="text-[10px]">
                    {c.isAllowed ? "ALLOWED" : "BLOCKED"}
                  </Badge>
                  <span className="font-mono">{c.sourceIp || "?"}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono">{c.destIp || "?"}</span>
                  <span className="text-muted-foreground">
                    {c.protocol ? PROTOCOL_LABELS[c.protocol] || c.protocol : ""}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

// =========================================================================
// ASSET INVENTORY
// =========================================================================

function AssetInventory({ assets }: { assets?: OtAsset[] }) {
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const filtered = (assets || []).filter((a) => {
    const matchesText =
      !filter ||
      a.name.toLowerCase().includes(filter.toLowerCase()) ||
      (a.ipAddress || "").toLowerCase().includes(filter.toLowerCase()) ||
      (a.vendor || "").toLowerCase().includes(filter.toLowerCase());
    const matchesType = typeFilter === "all" || a.assetType === typeFilter;
    return matchesText && matchesType;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Input
          placeholder="Search assets..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-w-sm"
        />
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="All Types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {Object.entries(ASSET_TYPE_LABELS).map(([value, info]) => (
              <SelectItem key={value} value={value}>
                {info.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {filtered.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Cpu className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">No OT assets found</p>
            <p className="text-xs text-muted-foreground mt-1">
              Add assets manually or deploy a passive OT sensor for auto-discovery
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3">
          {filtered.map((asset) => {
            const typeInfo = ASSET_TYPE_LABELS[asset.assetType];
            const Icon = typeInfo?.icon || Server;
            const levelInfo = asset.purdueLevel ? PURDUE_LEVEL_LABELS[asset.purdueLevel] : null;

            return (
              <Card key={asset.id}>
                <CardContent className="flex items-center gap-4 p-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                    <Icon className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium">{asset.name}</p>
                      {asset.isCritical ? (
                        <Badge variant="destructive" className="text-[10px]">
                          CRITICAL
                        </Badge>
                      ) : null}
                      {asset.isSafetySystem ? (
                        <Badge variant="outline" className="text-[10px] border-amber-700 text-amber-400">
                          SIS {asset.silRating || ""}
                        </Badge>
                      ) : null}
                      <StatusBadge status={asset.status} />
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span>{typeInfo?.label || asset.assetType}</span>
                      {asset.ipAddress ? <span className="font-mono">{asset.ipAddress}</span> : null}
                      {asset.vendor ? (
                        <span>
                          {asset.vendor} {asset.model || ""}
                        </span>
                      ) : null}
                      {levelInfo ? <span className={levelInfo.color}>{levelInfo.label}</span> : null}
                      {asset.discoveredBy ? <span>via {asset.discoveredBy}</span> : null}
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    {asset.cveCount > 0 ? (
                      <div className="flex items-center gap-1 text-red-400">
                        <FileWarning className="h-3 w-3" />
                        {asset.cveCount} CVE{asset.cveCount !== 1 ? "s" : ""}
                        {asset.highestCvss ? ` (${asset.highestCvss.toFixed(1)})` : ""}
                      </div>
                    ) : null}
                    {asset.lastSeen ? <p>Last seen: {new Date(asset.lastSeen).toLocaleDateString()}</p> : null}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// =========================================================================
// ANOMALY DASHBOARD
// =========================================================================

function AnomalyDashboard({ anomalies }: { anomalies?: OtAnomaly[] }) {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const resolveMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest(`/api/ot/anomalies/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: "resolved" }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ot/anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ot/stats"] });
      toast({ title: "Anomaly resolved" });
    },
  });

  const list = anomalies || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">OT Anomalies ({list.length})</h2>
      </div>

      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <CheckCircle className="h-10 w-10 text-green-500 mb-3" />
            <p className="text-sm text-muted-foreground">No anomalies detected</p>
            <p className="text-xs text-muted-foreground mt-1">OT/ICS network is operating within normal parameters</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {list.map((a) => (
            <Card key={a.id}>
              <CardContent className="flex items-start gap-4 p-4">
                <SeverityBadge severity={a.severity} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium">{a.title}</p>
                    <Badge variant="outline" className="text-[10px]">
                      {a.status}
                    </Badge>
                  </div>
                  {a.description ? (
                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{a.description}</p>
                  ) : null}
                  <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground flex-wrap">
                    <span>{ANOMALY_TYPE_LABELS[a.anomalyType] || a.anomalyType}</span>
                    {a.protocol ? <span className="font-mono">{PROTOCOL_LABELS[a.protocol] || a.protocol}</span> : null}
                    {a.sourceIp ? <span>src: {a.sourceIp}</span> : null}
                    {a.destIp ? <span>dst: {a.destIp}</span> : null}
                    {a.mitreTechnique ? (
                      <Badge variant="secondary" className="text-[10px]">
                        {a.mitreTechnique}
                      </Badge>
                    ) : null}
                    {a.icsCertAdvisory ? (
                      <Badge variant="secondary" className="text-[10px] border-amber-700">
                        {a.icsCertAdvisory}
                      </Badge>
                    ) : null}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-xs text-muted-foreground">{new Date(a.detectedAt).toLocaleString()}</p>
                  {a.status === "new" ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="mt-1 text-xs"
                      onClick={() => resolveMutation.mutate(a.id)}
                    >
                      Resolve
                    </Button>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// =========================================================================
// IT/OT BOUNDARY MONITOR
// =========================================================================

function BoundaryMonitor({ boundary }: { boundary?: Record<string, unknown> }) {
  const data = boundary as
    | {
        crossings?: OtConnection[];
        anomalies?: OtAnomaly[];
        totalCrossings?: number;
        allowedCrossings?: number;
        blockedCrossings?: number;
      }
    | undefined;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">IT/OT Boundary Monitor</h2>
        <p className="text-sm text-muted-foreground">
          Traffic crossing the air gap between IT (Level 4-5) and OT (Level 0-3) networks
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Total Crossings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data?.totalCrossings ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-green-400">Allowed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-400">{data?.allowedCrossings ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="border-red-800/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-red-400">Blocked / Unauthorized</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400">{data?.blockedCrossings ?? 0}</div>
          </CardContent>
        </Card>
      </div>

      {(data?.crossings || []).length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Shield className="h-10 w-10 text-green-500 mb-3" />
            <p className="text-sm text-muted-foreground">No boundary crossings detected</p>
            <p className="text-xs text-muted-foreground mt-1">The air gap between IT and OT networks is intact</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Boundary Crossing Connections</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(data?.crossings || []).map((c) => (
                <div key={c.id} className="flex items-center gap-3 rounded border p-3 text-xs">
                  <Badge variant={c.isAllowed ? "secondary" : "destructive"} className="text-[10px]">
                    {c.isAllowed ? "ALLOWED" : "BLOCKED"}
                  </Badge>
                  <div className="flex-1 flex items-center gap-2">
                    <span className="font-mono">{c.sourceIp || "?"}</span>
                    {c.sourcePurdueLevel ? (
                      <span className="text-muted-foreground">
                        ({PURDUE_LEVEL_LABELS[c.sourcePurdueLevel]?.label || c.sourcePurdueLevel})
                      </span>
                    ) : null}
                    <ArrowUpDown className="h-3 w-3 text-red-400" />
                    <span className="font-mono">{c.destIp || "?"}</span>
                    {c.destPurdueLevel ? (
                      <span className="text-muted-foreground">
                        ({PURDUE_LEVEL_LABELS[c.destPurdueLevel]?.label || c.destPurdueLevel})
                      </span>
                    ) : null}
                  </div>
                  {c.protocol ? (
                    <span className="text-muted-foreground">{PROTOCOL_LABELS[c.protocol] || c.protocol}</span>
                  ) : null}
                  {c.lastActivity ? (
                    <span className="text-muted-foreground">{new Date(c.lastActivity).toLocaleString()}</span>
                  ) : null}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {(data?.anomalies || []).length > 0 ? (
        <Card className="border-red-800/30">
          <CardHeader>
            <CardTitle className="text-sm text-red-400">Boundary Crossing Anomalies</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(data?.anomalies || []).map((a) => (
                <div key={a.id} className="flex items-center gap-3 text-xs">
                  <SeverityBadge severity={a.severity} />
                  <span className="flex-1">{a.title}</span>
                  <span className="text-muted-foreground">{new Date(a.detectedAt).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

// =========================================================================
// THREAT SIGNATURES
// =========================================================================

function ThreatSignatures({ signatures }: { signatures?: ThreatSignature[] }) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">OT Threat Signatures</h2>
        <p className="text-sm text-muted-foreground">
          {(signatures || []).length} ICS-specific detection rules for PLC manipulation, HMI anomalies, and protocol
          violations
        </p>
      </div>

      <div className="grid gap-3">
        {(signatures || []).map((sig) => (
          <Card key={sig.id}>
            <CardContent className="flex items-start gap-4 p-4">
              <SeverityBadge severity={sig.severity} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium">{sig.name}</p>
                  <Badge variant="outline" className="text-[10px] font-mono">
                    {sig.id}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{sig.description}</p>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <Badge variant="secondary" className="text-[10px]">
                    {PROTOCOL_LABELS[sig.protocol] || sig.protocol}
                  </Badge>
                  <Badge variant="secondary" className="text-[10px]">
                    {sig.mitreTactic}
                  </Badge>
                  <Badge variant="secondary" className="text-[10px]">
                    {sig.mitreTechnique}
                  </Badge>
                  {sig.icsCertAdvisory ? (
                    <Badge variant="outline" className="text-[10px] border-amber-700 text-amber-400">
                      {sig.icsCertAdvisory}
                    </Badge>
                  ) : null}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// =========================================================================
// ICS-CERT ADVISORIES
// =========================================================================

function IcsCertAdvisories({ advisories }: { advisories?: IcsCertAdvisory[] }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">ICS-CERT Advisories</h2>
          <p className="text-sm text-muted-foreground">
            CISA Industrial Control Systems advisories relevant to your OT environment
          </p>
        </div>
        <Button variant="outline" size="sm" asChild>
          <a href="https://www.cisa.gov/news-events/ics-advisories" target="_blank" rel="noopener noreferrer">
            <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
            CISA ICS-CERT
          </a>
        </Button>
      </div>

      <div className="grid gap-3">
        {(advisories || []).map((adv) => (
          <Card key={adv.id}>
            <CardContent className="p-4">
              <div className="flex items-start gap-4">
                <SeverityBadge severity={adv.severity} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-medium">{adv.title}</p>
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {adv.id}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">{adv.description}</p>

                  <div className="grid grid-cols-2 gap-x-6 gap-y-1 mt-3 text-xs">
                    <div>
                      <span className="text-muted-foreground">Vendor: </span>
                      <span>{adv.vendor}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Product: </span>
                      <span>{adv.product}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">CVSS: </span>
                      <span
                        className={adv.cvss >= 9 ? "text-red-400 font-bold" : adv.cvss >= 7 ? "text-orange-400" : ""}
                      >
                        {adv.cvss.toFixed(1)}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Affected: </span>
                      <span>{adv.affectedVersions}</span>
                    </div>
                  </div>

                  {adv.cveIds.length > 0 ? (
                    <div className="flex items-center gap-1 mt-2 flex-wrap">
                      {adv.cveIds.map((cve) => (
                        <Badge key={cve} variant="secondary" className="text-[10px] font-mono">
                          {cve}
                        </Badge>
                      ))}
                    </div>
                  ) : null}

                  <div className="mt-3 p-2 rounded bg-muted/50 text-xs">
                    <span className="font-medium">Mitigation: </span>
                    {adv.mitigation}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-xs text-muted-foreground">{new Date(adv.publishedAt).toLocaleDateString()}</p>
                  <Button variant="ghost" size="sm" className="mt-1 text-xs" asChild>
                    <a href={adv.url} target="_blank" rel="noopener noreferrer">
                      <BookOpen className="h-3 w-3 mr-1" />
                      Details
                    </a>
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

// =========================================================================
// CREATE ASSET DIALOG
// =========================================================================

function CreateAssetDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [assetType, setAssetType] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [vendor, setVendor] = useState("");
  const [model, setModel] = useState("");
  const [purdueLevel, setPurdueLevel] = useState("");
  const [description, setDescription] = useState("");
  const [isCritical, setIsCritical] = useState(false);
  const [isSafetySystem, setIsSafetySystem] = useState(false);
  const [silRating, setSilRating] = useState("");

  const queryClient = useQueryClient();
  const { toast } = useToast();

  const mutation = useMutation({
    mutationFn: () =>
      apiRequest("/api/ot/assets", {
        method: "POST",
        body: JSON.stringify({
          name,
          assetType,
          ipAddress: ipAddress || undefined,
          vendor: vendor || undefined,
          model: model || undefined,
          purdueLevel: purdueLevel || undefined,
          description: description || undefined,
          isCritical,
          isSafetySystem,
          silRating: silRating || undefined,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ot/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ot/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ot/topology"] });
      toast({ title: "OT asset created" });
      setOpen(false);
      setName("");
      setAssetType("");
      setIpAddress("");
      setVendor("");
      setModel("");
      setPurdueLevel("");
      setDescription("");
      setIsCritical(false);
      setIsSafetySystem(false);
      setSilRating("");
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create asset", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-1.5" />
          Add OT Asset
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Register OT Asset</DialogTitle>
          <DialogDescription>
            Manually register an industrial control system device. For passive discovery, deploy an OT sensor.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Name *</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="PLC-001" />
            </div>
            <div>
              <Label>Asset Type *</Label>
              <Select value={assetType} onValueChange={setAssetType}>
                <SelectTrigger>
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(ASSET_TYPE_LABELS).map(([value, info]) => (
                    <SelectItem key={value} value={value}>
                      {info.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>IP Address</Label>
              <Input value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="10.0.1.100" />
            </div>
            <div>
              <Label>Purdue Level</Label>
              <Select value={purdueLevel} onValueChange={setPurdueLevel}>
                <SelectTrigger>
                  <SelectValue placeholder="Auto-classify" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(PURDUE_LEVEL_LABELS).map(([value, info]) => (
                    <SelectItem key={value} value={value}>
                      {info.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Vendor</Label>
              <Input value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="Siemens" />
            </div>
            <div>
              <Label>Model</Label>
              <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="S7-1500" />
            </div>
          </div>

          <div>
            <Label>Description</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Main production line PLC"
              rows={2}
            />
          </div>

          <div className="flex items-center gap-6">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={isCritical}
                onChange={(e) => setIsCritical(e.target.checked)}
                className="rounded"
              />
              Critical Asset
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={isSafetySystem}
                onChange={(e) => setIsSafetySystem(e.target.checked)}
                className="rounded"
              />
              Safety System (SIS)
            </label>
          </div>

          {isSafetySystem ? (
            <div>
              <Label>SIL Rating</Label>
              <Select value={silRating} onValueChange={setSilRating}>
                <SelectTrigger>
                  <SelectValue placeholder="Select SIL" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="SIL 1">SIL 1</SelectItem>
                  <SelectItem value="SIL 2">SIL 2</SelectItem>
                  <SelectItem value="SIL 3">SIL 3</SelectItem>
                  <SelectItem value="SIL 4">SIL 4</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}

          <Button
            onClick={() => mutation.mutate()}
            disabled={!name || !assetType || mutation.isPending}
            className="w-full"
          >
            {mutation.isPending ? "Creating..." : "Register Asset"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// =========================================================================
// HELPERS
// =========================================================================

function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-800/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-800/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-800/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-800/30",
    informational: "bg-slate-500/20 text-slate-400 border-slate-800/30",
  };
  return (
    <Badge variant="outline" className={`text-[10px] uppercase ${variants[severity] || variants.medium}`}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, { color: string; icon: typeof CheckCircle }> = {
    online: { color: "text-green-400", icon: CheckCircle },
    offline: { color: "text-red-400", icon: XCircle },
    maintenance: { color: "text-amber-400", icon: Clock },
    unknown: { color: "text-muted-foreground", icon: Eye },
  };
  const v = variants[status] || variants.unknown;
  return (
    <span className={`flex items-center gap-1 text-[10px] ${v.color}`}>
      <v.icon className="h-2.5 w-2.5" />
      {status}
    </span>
  );
}
