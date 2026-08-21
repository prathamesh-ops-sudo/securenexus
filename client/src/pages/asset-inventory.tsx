import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Server,
  Monitor,
  Laptop,
  Smartphone,
  Network,
  Shield,
  Cloud,
  Database,
  HardDrive,
  Cpu,
  Printer,
  Box,
  Plus,
  Search,
  Filter,
  Upload,
  AlertTriangle,
  RefreshCw,
  Trash2,
  Edit,
  X,
  ChevronDown,
  BarChart3,
  TrendingUp,
  Eye,
  Globe,
  Wifi,
  Activity,
  FileCode,
  ShieldAlert,
  Scan,
  History,
  Link2,
  ArrowRight,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  Layers,
  GitBranch,
  Zap,
  Target,
  Radio,
  Package,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const ASSET_TYPE_ICONS: Record<string, React.ElementType> = {
  server: Server,
  workstation: Monitor,
  laptop: Laptop,
  mobile: Smartphone,
  network_device: Network,
  firewall: Shield,
  cloud_instance: Cloud,
  container: Box,
  database: Database,
  application: Cpu,
  iot_device: Cpu,
  printer: Printer,
  storage: HardDrive,
  virtual_machine: Server,
  other: HardDrive,
};

const CRITICALITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-green-500/10 text-green-500 border-green-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-green-500/10 text-green-500",
  procurement: "bg-blue-500/10 text-blue-500",
  maintenance: "bg-yellow-500/10 text-yellow-500",
  decommissioning: "bg-orange-500/10 text-orange-500",
  retired: "bg-zinc-500/10 text-zinc-500",
};

interface AssetStats {
  total: number;
  criticalCount: number;
  highCount: number;
  activeCount: number;
  avgRiskScore: number;
  totalVulnerabilities: number;
}

interface Asset {
  id: string;
  name: string;
  assetType: string;
  criticality: string;
  lifecycleStatus: string;
  environment: string;
  ipAddress: string | null;
  hostname: string | null;
  owner: string | null;
  department: string | null;
  location: string | null;
  operatingSystem: string | null;
  osVersion: string | null;
  manufacturer: string | null;
  model: string | null;
  riskScore: number;
  vulnerabilityCount: number;
  openFindings: number;
  tags: string[];
  lastSeenAt: string | null;
  createdAt: string;
}

function CreateAssetDialog({ onCreated }: { onCreated: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: "",
    assetType: "server",
    criticality: "medium",
    environment: "production",
    ipAddress: "",
    hostname: "",
    owner: "",
    department: "",
    location: "",
    operatingSystem: "",
    osVersion: "",
    manufacturer: "",
    model: "",
    notes: "",
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = {};
      for (const [k, v] of Object.entries(form)) {
        if (v) body[k] = v;
      }
      const res = await apiRequest("POST", "/api/assets", body);
      if (!res.ok) throw new Error("Failed to create asset");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Asset created" });
      setOpen(false);
      setForm({
        name: "",
        assetType: "server",
        criticality: "medium",
        environment: "production",
        ipAddress: "",
        hostname: "",
        owner: "",
        department: "",
        location: "",
        operatingSystem: "",
        osVersion: "",
        manufacturer: "",
        model: "",
        notes: "",
      });
      onCreated();
    },
    onError: () => toast({ title: "Error", description: "Failed to create asset", variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" /> Add Asset
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add New Asset</DialogTitle>
          <DialogDescription>Register a new asset in your inventory</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Label>Asset Name *</Label>
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g., Production Web Server 01"
            />
          </div>
          <div>
            <Label>Type</Label>
            <Select value={form.assetType} onValueChange={(v) => setForm({ ...form, assetType: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[
                  "server",
                  "workstation",
                  "laptop",
                  "mobile",
                  "network_device",
                  "firewall",
                  "cloud_instance",
                  "container",
                  "database",
                  "application",
                  "iot_device",
                  "printer",
                  "storage",
                  "virtual_machine",
                  "other",
                ].map((t) => (
                  <SelectItem key={t} value={t}>
                    {t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Criticality</Label>
            <Select value={form.criticality} onValueChange={(v) => setForm({ ...form, criticality: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Environment</Label>
            <Select value={form.environment} onValueChange={(v) => setForm({ ...form, environment: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="production">Production</SelectItem>
                <SelectItem value="staging">Staging</SelectItem>
                <SelectItem value="development">Development</SelectItem>
                <SelectItem value="testing">Testing</SelectItem>
                <SelectItem value="dr">DR</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>IP Address</Label>
            <Input
              value={form.ipAddress}
              onChange={(e) => setForm({ ...form, ipAddress: e.target.value })}
              placeholder="192.168.1.100"
            />
          </div>
          <div>
            <Label>Hostname</Label>
            <Input
              value={form.hostname}
              onChange={(e) => setForm({ ...form, hostname: e.target.value })}
              placeholder="web-server-01"
            />
          </div>
          <div>
            <Label>Owner</Label>
            <Input
              value={form.owner}
              onChange={(e) => setForm({ ...form, owner: e.target.value })}
              placeholder="IT Operations"
            />
          </div>
          <div>
            <Label>Department</Label>
            <Input
              value={form.department}
              onChange={(e) => setForm({ ...form, department: e.target.value })}
              placeholder="Engineering"
            />
          </div>
          <div>
            <Label>Location</Label>
            <Input
              value={form.location}
              onChange={(e) => setForm({ ...form, location: e.target.value })}
              placeholder="Mumbai DC / AWS us-east-1"
            />
          </div>
          <div>
            <Label>OS</Label>
            <Input
              value={form.operatingSystem}
              onChange={(e) => setForm({ ...form, operatingSystem: e.target.value })}
              placeholder="Ubuntu 22.04"
            />
          </div>
          <div>
            <Label>Manufacturer</Label>
            <Input
              value={form.manufacturer}
              onChange={(e) => setForm({ ...form, manufacturer: e.target.value })}
              placeholder="Dell / AWS"
            />
          </div>
          <div>
            <Label>Model</Label>
            <Input
              value={form.model}
              onChange={(e) => setForm({ ...form, model: e.target.value })}
              placeholder="PowerEdge R740 / t3.medium"
            />
          </div>
          <div className="col-span-2">
            <Label>Notes</Label>
            <Textarea
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
              placeholder="Additional notes about this asset..."
              rows={2}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => createMutation.mutate()} disabled={!form.name || createMutation.isPending}>
            {createMutation.isPending ? "Creating..." : "Create Asset"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function AssetInventoryPage() {
  usePageTitle("Asset Inventory");
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [critFilter, setCritFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const { data, isLoading, refetch } = useQuery<{ assets: Asset[]; stats: AssetStats }>({
    queryKey: ["/api/assets", search, typeFilter, critFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (typeFilter !== "all") params.set("type", typeFilter);
      if (critFilter !== "all") params.set("criticality", critFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      const res = await apiRequest("GET", `/api/assets?${params}`);
      return res.json();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("DELETE", `/api/assets/${id}`);
      if (!res.ok) throw new Error("Failed to delete");
    },
    onSuccess: () => {
      toast({ title: "Asset deleted" });
      refetch();
    },
  });

  const assets = data?.assets || [];
  const stats = data?.stats || {
    total: 0,
    criticalCount: 0,
    highCount: 0,
    activeCount: 0,
    avgRiskScore: 0,
    totalVulnerabilities: 0,
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Server className="h-6 w-6" /> Asset Inventory
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Complete inventory of all organizational assets with risk scoring
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <CreateAssetDialog onCreated={() => refetch()} />
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-primary" />
              <div>
                <p className="text-2xl font-bold">{stats.total}</p>
                <p className="text-xs text-muted-foreground">Total Assets</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Monitor className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{stats.activeCount}</p>
                <p className="text-xs text-muted-foreground">Active</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-2xl font-bold">{stats.criticalCount}</p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-2xl font-bold">{stats.highCount}</p>
                <p className="text-xs text-muted-foreground">High Risk</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">{stats.avgRiskScore}</p>
                <p className="text-xs text-muted-foreground">Avg Risk</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-2xl font-bold">{stats.totalVulnerabilities}</p>
                <p className="text-xs text-muted-foreground">Vulnerabilities</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search assets by name, hostname, IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {[
              "server",
              "workstation",
              "laptop",
              "cloud_instance",
              "network_device",
              "firewall",
              "database",
              "application",
              "container",
              "virtual_machine",
            ].map((t) => (
              <SelectItem key={t} value={t}>
                {t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={critFilter} onValueChange={setCritFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Criticality" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Criticality</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="procurement">Procurement</SelectItem>
            <SelectItem value="maintenance">Maintenance</SelectItem>
            <SelectItem value="decommissioning">Decommissioning</SelectItem>
            <SelectItem value="retired">Retired</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Tabs for different views */}
      <Tabs defaultValue="inventory" className="space-y-4">
        <TabsList>
          <TabsTrigger value="inventory" className="gap-1">
            <Server className="h-3.5 w-3.5" /> Inventory
          </TabsTrigger>
          <TabsTrigger value="topology" className="gap-1">
            <GitBranch className="h-3.5 w-3.5" /> Topology
          </TabsTrigger>
          <TabsTrigger value="discovery" className="gap-1">
            <Radio className="h-3.5 w-3.5" /> Auto-Discovery
          </TabsTrigger>
          <TabsTrigger value="lifecycle" className="gap-1">
            <Activity className="h-3.5 w-3.5" /> Lifecycle
          </TabsTrigger>
          <TabsTrigger value="import" className="gap-1">
            <Layers className="h-3.5 w-3.5" /> Import Sources
          </TabsTrigger>
        </TabsList>

        <TabsContent value="inventory">
          {assets.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-16 gap-4">
                <Server className="h-12 w-12 text-muted-foreground/40" />
                <div className="text-center">
                  <h3 className="font-semibold">No assets found</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    {search
                      ? "No assets match your search criteria"
                      : "Add your first asset to start building your inventory"}
                  </p>
                </div>
                {!search && <CreateAssetDialog onCreated={() => refetch()} />}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {assets.map((asset) => {
                const Icon = ASSET_TYPE_ICONS[asset.assetType] || HardDrive;
                return (
                  <Card key={asset.id} className="transition-all hover:shadow-sm">
                    <CardContent className="py-3">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-muted">
                          <Icon className="h-5 w-5 text-muted-foreground" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="font-semibold text-sm truncate">{asset.name}</span>
                            <Badge className={CRITICALITY_COLORS[asset.criticality] || ""} variant="outline">
                              {asset.criticality}
                            </Badge>
                            <Badge className={STATUS_COLORS[asset.lifecycleStatus] || ""} variant="outline">
                              {asset.lifecycleStatus}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>{asset.assetType.replace(/_/g, " ")}</span>
                            {asset.ipAddress && <span>{asset.ipAddress}</span>}
                            {asset.hostname && <span>{asset.hostname}</span>}
                            {asset.owner && <span>Owner: {asset.owner}</span>}
                            {asset.department && <span>{asset.department}</span>}
                            {asset.operatingSystem && <span>{asset.operatingSystem}</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-3 text-right">
                          <div>
                            <p className="text-sm font-bold">{asset.riskScore}</p>
                            <p className="text-[10px] text-muted-foreground">Risk</p>
                          </div>
                          <div>
                            <p className="text-sm font-bold">{asset.vulnerabilityCount}</p>
                            <p className="text-[10px] text-muted-foreground">Vulns</p>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-muted-foreground hover:text-destructive"
                            onClick={() => deleteMutation.mutate(asset.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* 45.3 — Topology */}
        <TabsContent value="topology">
          <AssetTopologyPanel />
        </TabsContent>

        {/* 45.5 — Auto-Discovery */}
        <TabsContent value="discovery">
          <AssetAutoDiscoveryPanel />
        </TabsContent>

        {/* 45.6 — Lifecycle */}
        <TabsContent value="lifecycle">
          <AssetLifecyclePanel />
        </TabsContent>

        {/* 45.4 — Import Sources */}
        <TabsContent value="import">
          <AssetImportSourcesPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// 45.1 — Asset Detail Panel (shown when clicking an asset)
function AssetDetailPanel({ assetId, onClose }: { assetId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/assets", assetId, "full-context"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/assets/${assetId}/full-context`);
      return res.json();
    },
    enabled: !!assetId,
  });

  if (isLoading)
    return (
      <Card>
        <CardContent className="py-8 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );
  if (!data) return null;

  const asset = data.asset;
  const vulnBreakdown = data.vulnerabilityBreakdown;

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Eye className="h-4 w-4" /> {asset?.name}
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-2 rounded border bg-muted/10">
            <p className="text-[10px] text-muted-foreground">OS</p>
            <p className="text-xs font-medium">{asset?.operatingSystem || "N/A"}</p>
          </div>
          <div className="p-2 rounded border bg-muted/10">
            <p className="text-[10px] text-muted-foreground">IP</p>
            <p className="text-xs font-medium font-mono">{asset?.ipAddress || "N/A"}</p>
          </div>
          <div className="p-2 rounded border bg-muted/10">
            <p className="text-[10px] text-muted-foreground">Risk Score</p>
            <p className="text-xs font-bold">{asset?.riskScore || 0}</p>
          </div>
          <div className="p-2 rounded border bg-muted/10">
            <p className="text-[10px] text-muted-foreground">Last Seen</p>
            <p className="text-xs font-medium">
              {asset?.lastSeenAt ? new Date(asset.lastSeenAt).toLocaleDateString() : "N/A"}
            </p>
          </div>
        </div>

        {/* Vulnerability Breakdown */}
        <div>
          <p className="text-xs font-medium mb-2">Vulnerability Breakdown</p>
          {vulnBreakdown ? (
            <div className="flex gap-2">
              <Badge variant="destructive" className="text-[10px]">
                Critical: {vulnBreakdown.critical}
              </Badge>
              <Badge variant="outline" className="text-[10px] border-orange-500/30 text-orange-500">
                High: {vulnBreakdown.high}
              </Badge>
              <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-500">
                Medium: {vulnBreakdown.medium}
              </Badge>
              <Badge variant="outline" className="text-[10px]">
                Low: {vulnBreakdown.low}
              </Badge>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              Unavailable: connect a vulnerability scanner to collect severity-level findings.
            </p>
          )}
        </div>

        {/* Software */}
        <div>
          <p className="text-xs font-medium mb-2 flex items-center gap-1">
            <Package className="h-3 w-3" /> Software Inventory
          </p>
          <div className="space-y-1">
            {data.softwareInventory.length > 0 ? (
              data.softwareInventory.map((s: any) => (
                <div key={s.name} className="flex items-center gap-2 text-xs p-1.5 rounded border">
                  <span className="font-mono font-medium">{s.name}</span>
                  <Badge variant="outline" className="text-[10px]">
                    {s.version}
                  </Badge>
                  {s.cveCount > 0 && (
                    <Badge variant="destructive" className="text-[10px]">
                      {s.cveCount} CVEs
                    </Badge>
                  )}
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">{data.availability?.softwareInventory?.reason}</p>
            )}
          </div>
        </div>

        {/* Open Ports */}
        <div>
          <p className="text-xs font-medium mb-2 flex items-center gap-1">
            <Wifi className="h-3 w-3" /> Open Ports
          </p>
          <p className="text-xs text-muted-foreground">
            {data.openPorts.length > 0
              ? data.openPorts.join(", ")
              : data.availability?.network?.reason || "Unavailable: no port telemetry collected."}
          </p>
        </div>

        {/* Alert History */}
        <div>
          <p className="text-xs font-medium mb-2 flex items-center gap-1">
            <ShieldAlert className="h-3 w-3" /> Recent Alerts
          </p>
          <div className="space-y-1">
            {data.alertHistory.length > 0 ? (
              data.alertHistory.map((a: any) => (
                <div key={a.id} className="flex items-center gap-2 text-xs p-1.5 rounded border">
                  <Badge
                    variant={a.severity === "critical" || a.severity === "high" ? "destructive" : "outline"}
                    className="text-[10px]"
                  >
                    {a.severity}
                  </Badge>
                  <span className="flex-1 truncate">{a.title}</span>
                  <span className="text-muted-foreground">{new Date(a.createdAt).toLocaleDateString()}</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">{data.availability?.securityHistory?.reason}</p>
            )}
          </div>
        </div>

        {/* Compliance */}
        <div>
          <p className="text-xs font-medium mb-2 flex items-center gap-1">
            <Shield className="h-3 w-3" /> Compliance
          </p>
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium">Not assessed</span>
            <span className="text-xs text-muted-foreground">{data.complianceStatus?.reason}</span>
            {(data.complianceStatus?.frameworks || []).map((f: string) => (
              <Badge key={f} variant="outline" className="text-[10px]">
                {f}
              </Badge>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// 45.3 — Asset Topology Panel
function AssetTopologyPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/assets/topology"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/assets/topology");
      return res.json();
    },
  });

  if (isLoading)
    return (
      <Card>
        <CardContent className="py-8 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  const segments = data?.segments || [];
  const internetFacing = nodes.filter((n: any) => n.internetFacing);

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium flex items-center gap-2">
          <GitBranch className="h-5 w-5" /> Network Topology
        </h3>
        <p className="text-sm text-muted-foreground">Asset relationships and network segments</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{nodes.length}</p>
            <p className="text-xs text-muted-foreground">Total Nodes</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{edges.length}</p>
            <p className="text-xs text-muted-foreground">Connections</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold text-red-500">{internetFacing.length}</p>
            <p className="text-xs text-muted-foreground">Internet-Facing</p>
          </CardContent>
        </Card>
      </div>

      {segments.map((seg: any) => (
        <Card key={seg.name}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              {seg.name} Segment ({seg.assets.length} assets)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {nodes
                .filter((n: any) => seg.assets.includes(n.id))
                .slice(0, 20)
                .map((n: any) => (
                  <Badge
                    key={n.id}
                    variant="outline"
                    className={`text-[10px] ${n.internetFacing ? "border-red-500/30 text-red-500" : ""}`}
                  >
                    {n.internetFacing && <Globe className="h-2.5 w-2.5 mr-0.5" />}
                    {n.label}
                  </Badge>
                ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// 45.5 — Auto-Discovery Panel
function AssetAutoDiscoveryPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/assets/auto-discovery"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/assets/auto-discovery");
      return res.json();
    },
  });

  if (isLoading)
    return (
      <Card>
        <CardContent className="py-8 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium flex items-center gap-2">
            <Radio className="h-5 w-5" /> Asset Auto-Discovery
          </h3>
          <p className="text-sm text-muted-foreground">
            Continuously discover new assets from network scans, EDR, and cloud APIs
          </p>
        </div>
        <Badge variant={data?.enabled ? "default" : "outline"}>{data?.enabled ? "Enabled" : "Disabled"}</Badge>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {(data?.sources || []).map((src: any) => (
          <Card key={src.type}>
            <CardContent className="pt-4">
              <div className="flex items-center gap-2 mb-2">
                <Scan className="h-4 w-4 text-muted-foreground" />
                <span className="text-xs font-medium">{src.type.replace(/_/g, " ")}</span>
                <Badge variant={src.enabled ? "default" : "outline"} className="text-[10px] ml-auto">
                  {src.enabled ? "On" : "Off"}
                </Badge>
              </div>
              <p className="text-lg font-bold">{src.totalDiscovered}</p>
              <p className="text-[10px] text-muted-foreground">discovered &middot; {src.lastFound} new last scan</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="h-4 w-4 text-yellow-500" /> Recently Discovered
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {(data?.recentlyDiscovered || []).map((d: any) => (
              <div key={d.name} className="flex items-center gap-3 p-2 rounded border text-xs">
                <div
                  className={`w-2 h-2 rounded-full ${d.inInventory ? "bg-green-500" : "bg-yellow-500 animate-pulse"}`}
                />
                <span className="font-medium flex-1">{d.name}</span>
                <span className="font-mono text-muted-foreground">{d.ipAddress}</span>
                <Badge variant="outline" className="text-[10px]">
                  {d.discoveredBy.replace(/_/g, " ")}
                </Badge>
                <Badge variant={d.inInventory ? "default" : "destructive"} className="text-[10px]">
                  {d.inInventory ? "Known" : "New"}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// 45.6 — Lifecycle Panel
function AssetLifecyclePanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/assets/lifecycle-summary"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/assets/lifecycle-summary");
      return res.json();
    },
  });

  if (isLoading)
    return (
      <Card>
        <CardContent className="py-8 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );

  const lifecycle = data?.lifecycle || {};
  const zombies = data?.zombieAssets || [];
  const stages = [
    { key: "provisioned", label: "Provisioned", color: "bg-blue-500" },
    { key: "active", label: "Active", color: "bg-green-500" },
    { key: "maintenance", label: "Maintenance", color: "bg-yellow-500" },
    { key: "decommissioning", label: "Decommissioning", color: "bg-orange-500" },
    { key: "decommissioned", label: "Decommissioned", color: "bg-zinc-500" },
  ];

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium flex items-center gap-2">
          <Activity className="h-5 w-5" /> Asset Lifecycle
        </h3>
        <p className="text-sm text-muted-foreground">Track assets through provisioned to decommissioned stages</p>
      </div>

      <div className="flex items-center gap-2">
        {stages.map((s, i) => (
          <div key={s.key} className="flex items-center gap-2">
            <div className="text-center">
              <div
                className={`w-12 h-12 rounded-full ${s.color} flex items-center justify-center text-white font-bold text-sm`}
              >
                {lifecycle[s.key] || 0}
              </div>
              <p className="text-[10px] text-muted-foreground mt-1">{s.label}</p>
            </div>
            {i < stages.length - 1 && <ArrowRight className="h-4 w-4 text-muted-foreground" />}
          </div>
        ))}
      </div>

      {zombies.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-yellow-500">
              <AlertTriangle className="h-4 w-4" /> Zombie Assets ({zombies.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-3">Assets marked as active but not seen in 30+ days</p>
            <div className="space-y-1">
              {zombies.map((z: any) => (
                <div
                  key={z.id}
                  className="flex items-center gap-3 text-xs p-2 rounded border border-yellow-500/20 bg-yellow-500/5"
                >
                  <span className="font-medium flex-1">{z.name}</span>
                  <span className="text-muted-foreground">{z.daysSinceLastSeen} days since last seen</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// 45.4 — Import Sources Panel
function AssetImportSourcesPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/assets/import-sources"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/assets/import-sources");
      return res.json();
    },
  });

  if (isLoading)
    return (
      <Card>
        <CardContent className="py-8 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );

  const sources = data?.sources || [];

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium flex items-center gap-2">
          <Layers className="h-5 w-5" /> Asset Import Sources
        </h3>
        <p className="text-sm text-muted-foreground">
          Import assets from Active Directory, cloud providers, EDR agents, and more
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {sources.map((src: any) => {
          const connected = src.status === "connected";
          return (
            <Card key={src.id}>
              <CardContent className="py-3">
                <div className="flex items-center gap-3">
                  <div
                    className={`w-10 h-10 rounded-lg flex items-center justify-center ${connected ? "bg-green-500/10" : "bg-muted"}`}
                  >
                    {src.type === "cloud" ? (
                      <Cloud className="h-5 w-5" />
                    ) : src.type === "directory" ? (
                      <Database className="h-5 w-5" />
                    ) : src.type === "agent" ? (
                      <Cpu className="h-5 w-5" />
                    ) : (
                      <Upload className="h-5 w-5" />
                    )}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{src.name}</span>
                      <Badge variant={connected ? "default" : "outline"} className="text-[10px]">
                        {src.status}
                      </Badge>
                    </div>
                    <div className="flex gap-3 text-xs text-muted-foreground mt-0.5">
                      <span>{src.assetCount} assets</span>
                      {src.lastSync && <span>Synced {new Date(src.lastSync).toLocaleDateString()}</span>}
                    </div>
                  </div>
                  <Button variant="outline" size="sm" className="text-xs h-7" disabled={connected}>
                    {connected ? "Connected" : "Connect"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
