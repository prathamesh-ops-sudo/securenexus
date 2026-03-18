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
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  Atom,
  Plus,
  Search,
  Shield,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  ShieldCheck,
  Clock,
  ArrowRight,
  Loader2,
  Lock,
  Key,
  Server,
  FileText,
  TrendingUp,
  BarChart3,
  Trash2,
  ChevronRight,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { FormPageSkeleton } from "@/components/page-skeleton";

// ── Types ─────────────────────────────────────────────────────────

interface CryptoAsset {
  id: string;
  orgId: string;
  assetName: string;
  algorithm: string;
  keyLength: number | null;
  source: string;
  hostname: string | null;
  port: number | null;
  serviceName: string | null;
  filePath: string | null;
  expiresAt: string | null;
  isQuantumVulnerable: boolean;
  quantumRiskLevel: string;
  isHardcoded: boolean;
  canBeUpgraded: boolean;
  pqcReplacement: string | null;
  migrationStatus: string;
  migrationPriority: number;
  migrationNotes: string | null;
  lastScannedAt: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

interface RiskScore {
  overallScore: number;
  cryptoAgility: number;
  algorithmDiversity: number;
  pqcReadiness: number;
  complianceScore: number;
  totalAssets: number;
  vulnerableAssets: number;
  migratedAssets: number;
  criticalRiskCount: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  estimatedMigrationMonths: number;
}

interface MigrationPhase {
  phase: number;
  phaseName: string;
  description: string;
  assets: Array<{
    id: string;
    assetName: string;
    algorithm: string;
    replacement: string;
    priority: number;
  }>;
  estimatedWeeks: number;
}

interface MigrationTask {
  id: string;
  orgId: string;
  title: string;
  description: string | null;
  cryptoInventoryId: string | null;
  currentAlgorithm: string;
  targetAlgorithm: string;
  priority: string;
  status: string;
  effortEstimateDays: number | null;
  assignedTo: string | null;
  dueDate: string | null;
  completedAt: string | null;
  blockers: string | null;
  nistStandard: string | null;
  createdAt: string;
  updatedAt: string;
}

interface AgilityAssessment {
  totalAssets: number;
  hardcodedCount: number;
  configurableCount: number;
  agilityScore: number;
  hardcodedAssets: Array<{
    id: string;
    assetName: string;
    algorithm: string;
    source: string;
    filePath: string | null;
  }>;
  recommendations: string[];
}

interface NistCompliance {
  [key: string]: {
    standard: string;
    name: string;
    description: string;
    status: "not_started" | "in_progress" | "compliant";
    progress: number;
    relevantAssets: number;
    migratedAssets: number;
  };
}

interface DashboardData {
  riskScore: RiskScore;
  nistCompliance: NistCompliance;
  agility: AgilityAssessment;
  inventory: { total: number; vulnerable: number };
  migration: { totalTasks: number; completedTasks: number };
  recentScans: Array<{
    id: string;
    scanType: string;
    status: string;
    assetsDiscovered: number;
    vulnerableFound: number;
    startedAt: string;
    completedAt: string | null;
  }>;
  enums: {
    algorithmTypes: readonly string[];
    riskLevels: readonly string[];
    assetSources: readonly string[];
    migrationStatuses: readonly string[];
    nistStandards: readonly string[];
  };
}

// ── Helpers ───────────────────────────────────────────────────────

function riskColor(level: string): string {
  switch (level) {
    case "critical":
      return "bg-red-500/10 text-red-500 border-red-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium":
      return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    case "low":
      return "bg-blue-500/10 text-blue-500 border-blue-500/20";
    case "safe":
      return "bg-green-500/10 text-green-500 border-green-500/20";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function statusColor(status: string): string {
  switch (status) {
    case "not_started":
      return "bg-slate-500/10 text-slate-500";
    case "assessed":
      return "bg-blue-500/10 text-blue-500";
    case "planned":
      return "bg-purple-500/10 text-purple-500";
    case "in_progress":
      return "bg-yellow-500/10 text-yellow-500";
    case "migrated":
      return "bg-green-500/10 text-green-500";
    case "verified":
      return "bg-emerald-500/10 text-emerald-500";
    case "deferred":
      return "bg-muted text-muted-foreground";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function nistStatusColor(status: string): string {
  switch (status) {
    case "compliant":
      return "text-green-500";
    case "in_progress":
      return "text-yellow-500";
    default:
      return "text-slate-500";
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-500";
  if (score >= 60) return "text-yellow-500";
  if (score >= 40) return "text-orange-500";
  return "text-red-500";
}

function progressColor(score: number): string {
  if (score >= 80) return "bg-green-500";
  if (score >= 60) return "bg-yellow-500";
  if (score >= 40) return "bg-orange-500";
  return "bg-red-500";
}

function sourceLabel(source: string): string {
  return source
    .split("_")
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

function formatDate(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString();
}

const ALGORITHM_CATEGORIES = {
  asymmetric: [
    "RSA-1024",
    "RSA-2048",
    "RSA-3072",
    "RSA-4096",
    "ECDSA-P256",
    "ECDSA-P384",
    "ECDSA-P521",
    "ECDH-P256",
    "ECDH-P384",
    "Ed25519",
    "DH-2048",
    "DH-4096",
    "DSA-1024",
    "DSA-2048",
  ],
  symmetric: ["AES-128", "AES-256", "3DES", "ChaCha20-Poly1305"],
  hash: ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5", "HMAC-SHA256"],
  pqc: ["CRYSTALS-Kyber", "CRYSTALS-Dilithium", "FALCON", "SPHINCS+", "BIKE", "HQC"],
};

// ── Main Component ────────────────────────────────────────────────

export default function QuantumReadinessPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const [inventorySearch, setInventorySearch] = useState("");
  const [algorithmFilter, setAlgorithmFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [addAssetOpen, setAddAssetOpen] = useState(false);
  const [addTaskOpen, setAddTaskOpen] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  // ── Data Fetching ─────────────────────────────────────────────

  const { data: dashboard, isLoading: dashboardLoading } = useQuery<DashboardData>({
    queryKey: ["/api/quantum-readiness/dashboard"],
  });

  const { data: inventoryData, isLoading: inventoryLoading } = useQuery<{
    items: CryptoAsset[];
    total: number;
  }>({
    queryKey: ["/api/quantum-readiness/inventory", inventorySearch, algorithmFilter, riskFilter, sourceFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (inventorySearch) params.set("search", inventorySearch);
      if (algorithmFilter !== "all") params.set("algorithm", algorithmFilter);
      if (riskFilter !== "all") params.set("riskLevel", riskFilter);
      if (sourceFilter !== "all") params.set("source", sourceFilter);
      params.set("limit", "100");
      return apiRequest("GET", `/api/quantum-readiness/inventory?${params.toString()}`).then((r) => r.json());
    },
  });

  const { data: roadmap } = useQuery<MigrationPhase[]>({
    queryKey: ["/api/quantum-readiness/migration-roadmap"],
  });

  const { data: tasksData } = useQuery<{ items: MigrationTask[]; total: number }>({
    queryKey: ["/api/quantum-readiness/migration-tasks"],
  });

  const { data: nistCompliance } = useQuery<NistCompliance>({
    queryKey: ["/api/quantum-readiness/nist-compliance"],
  });

  const { data: agility } = useQuery<AgilityAssessment>({
    queryKey: ["/api/quantum-readiness/algorithm-agility"],
  });

  // ── Mutations ─────────────────────────────────────────────────

  const addAssetMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/quantum-readiness/inventory", data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Crypto asset added" });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/inventory"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/dashboard"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/migration-roadmap"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/nist-compliance"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/algorithm-agility"] });
      setAddAssetOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to add asset", description: err.message, variant: "destructive" });
    },
  });

  const deleteAssetMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/quantum-readiness/inventory/${id}`),
    onSuccess: () => {
      toast({ title: "Crypto asset removed" });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/inventory"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/dashboard"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/migration-roadmap"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/algorithm-agility"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete asset", description: err.message, variant: "destructive" });
    },
  });

  const updateAssetMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      apiRequest("PATCH", `/api/quantum-readiness/inventory/${id}`, data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Crypto asset updated" });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/inventory"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/dashboard"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update", description: err.message, variant: "destructive" });
    },
  });

  const addTaskMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/quantum-readiness/migration-tasks", data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Migration task created" });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/migration-tasks"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/dashboard"] });
      setAddTaskOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create task", description: err.message, variant: "destructive" });
    },
  });

  const updateTaskMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      apiRequest("PATCH", `/api/quantum-readiness/migration-tasks/${id}`, data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Task updated" });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/migration-tasks"] });
      qc.invalidateQueries({ queryKey: ["/api/quantum-readiness/dashboard"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update task", description: err.message, variant: "destructive" });
    },
  });

  const snapshotMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/quantum-readiness/risk-score/snapshot").then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Risk score snapshot saved" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to save snapshot", description: err.message, variant: "destructive" });
    },
  });

  const score = dashboard?.riskScore;
  const inventory = inventoryData?.items || [];
  const tasks = tasksData?.items || [];
  const phases = roadmap || [];

  // ── Render ────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Quantum Readiness Assessment</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Cryptographic inventory, quantum vulnerability scoring, and post-quantum migration planning
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => snapshotMutation.mutate()}
            disabled={snapshotMutation.isPending}
          >
            {snapshotMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <BarChart3 className="h-4 w-4 mr-1" />
            )}
            Save Snapshot
          </Button>
          <Dialog open={addAssetOpen} onOpenChange={setAddAssetOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-1" />
                Add Crypto Asset
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Add Cryptographic Asset</DialogTitle>
                <DialogDescription>
                  Register a cryptographic asset for quantum vulnerability assessment
                </DialogDescription>
              </DialogHeader>
              <AddAssetForm
                onSubmit={(data) => addAssetMutation.mutate(data)}
                isPending={addAssetMutation.isPending}
                enums={dashboard?.enums}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <Atom className="h-4 w-4 text-muted-foreground" />
              <span className="text-xs text-muted-foreground">Quantum Readiness</span>
            </div>
            <div className={`text-2xl font-semibold ${scoreColor(score?.overallScore || 0)}`}>
              {score?.overallScore || 0}%
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {(score?.overallScore || 0) >= 80 ? "Strong" : (score?.overallScore || 0) >= 50 ? "Moderate" : "At Risk"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <Key className="h-4 w-4 text-blue-500" />
              <span className="text-xs text-muted-foreground">Crypto Assets</span>
            </div>
            <div className="text-2xl font-semibold">{score?.totalAssets || 0}</div>
            <div className="text-xs text-muted-foreground mt-1">{score?.vulnerableAssets || 0} vulnerable</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              <span className="text-xs text-muted-foreground">Critical & High</span>
            </div>
            <div className="text-2xl font-semibold text-red-500">
              {(score?.criticalRiskCount || 0) + (score?.highRiskCount || 0)}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {score?.criticalRiskCount || 0} critical, {score?.highRiskCount || 0} high
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              <span className="text-xs text-muted-foreground">Migrated</span>
            </div>
            <div className="text-2xl font-semibold text-green-500">{score?.migratedAssets || 0}</div>
            <div className="text-xs text-muted-foreground mt-1">of {score?.vulnerableAssets || 0} vulnerable</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="h-4 w-4 text-yellow-500" />
              <span className="text-xs text-muted-foreground">Est. Migration</span>
            </div>
            <div className="text-2xl font-semibold">{score?.estimatedMigrationMonths || 0} mo</div>
            <div className="text-xs text-muted-foreground mt-1">to full PQC readiness</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="inventory">Crypto Inventory</TabsTrigger>
          <TabsTrigger value="roadmap">Migration Roadmap</TabsTrigger>
          <TabsTrigger value="tasks">Migration Tasks</TabsTrigger>
          <TabsTrigger value="nist">NIST PQC Compliance</TabsTrigger>
          <TabsTrigger value="agility">Algorithm Agility</TabsTrigger>
        </TabsList>

        {/* ── Overview Tab ──────────────────────────────────────── */}
        <TabsContent value="overview" className="space-y-6">
          {/* Score Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Readiness Score Breakdown</CardTitle>
                <CardDescription>Component scores contributing to overall quantum readiness</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {[
                  {
                    label: "Crypto Agility",
                    value: score?.cryptoAgility || 0,
                    description: "% of assets with configurable algorithms",
                  },
                  {
                    label: "Algorithm Diversity",
                    value: score?.algorithmDiversity || 0,
                    description: "Variety of algorithms across inventory",
                  },
                  {
                    label: "PQC Readiness",
                    value: score?.pqcReadiness || 0,
                    description: "% of assets using post-quantum algorithms",
                  },
                  {
                    label: "NIST Compliance",
                    value: score?.complianceScore || 0,
                    description: "Alignment with NIST PQC standards",
                  },
                ].map((item) => (
                  <div key={item.label}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium">{item.label}</span>
                      <span className={`text-sm font-semibold ${scoreColor(item.value)}`}>{item.value}%</span>
                    </div>
                    <Progress value={item.value} className="h-2" />
                    <p className="text-xs text-muted-foreground mt-1">{item.description}</p>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Risk Distribution</CardTitle>
                <CardDescription>Crypto assets by quantum vulnerability level</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  { level: "Critical", count: score?.criticalRiskCount || 0, color: "bg-red-500" },
                  { level: "High", count: score?.highRiskCount || 0, color: "bg-orange-500" },
                  { level: "Medium", count: score?.mediumRiskCount || 0, color: "bg-yellow-500" },
                  { level: "Low", count: score?.lowRiskCount || 0, color: "bg-blue-500" },
                  {
                    level: "Safe",
                    count: Math.max(
                      0,
                      (score?.totalAssets || 0) -
                        (score?.criticalRiskCount || 0) -
                        (score?.highRiskCount || 0) -
                        (score?.mediumRiskCount || 0) -
                        (score?.lowRiskCount || 0),
                    ),
                    color: "bg-green-500",
                  },
                ].map((item) => {
                  const total = score?.totalAssets || 1;
                  const pct = Math.round((item.count / total) * 100);
                  return (
                    <div key={item.level} className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${item.color}`} />
                      <span className="text-sm w-16">{item.level}</span>
                      <div className="flex-1 bg-muted rounded-full h-2">
                        <div className={`h-2 rounded-full ${item.color}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-sm font-medium w-8 text-right">{item.count}</span>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>

          {/* NIST Overview */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">NIST Post-Quantum Standards</CardTitle>
              <CardDescription>Compliance status with NIST FIPS post-quantum cryptography standards</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {nistCompliance &&
                  Object.entries(nistCompliance).map(([key, std]) => (
                    <div key={key} className="border rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-semibold">{std.standard}</span>
                        <Badge variant="outline" className={nistStatusColor(std.status)}>
                          {std.status === "compliant"
                            ? "Compliant"
                            : std.status === "in_progress"
                              ? "In Progress"
                              : "Not Started"}
                        </Badge>
                      </div>
                      <p className="text-xs font-medium mb-1">{std.name}</p>
                      <Progress value={std.progress} className="h-1.5 mb-2" />
                      <p className="text-xs text-muted-foreground">
                        {std.migratedAssets} of {std.relevantAssets + std.migratedAssets} assets migrated
                      </p>
                    </div>
                  ))}
              </div>
            </CardContent>
          </Card>

          {/* Algorithm Agility Summary */}
          {agility && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Algorithm Agility</CardTitle>
                <CardDescription>Ability to rapidly swap cryptographic algorithms when needed</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-6 mb-4">
                  <div>
                    <div className={`text-3xl font-semibold ${scoreColor(agility.agilityScore)}`}>
                      {agility.agilityScore}%
                    </div>
                    <div className="text-xs text-muted-foreground">Agility Score</div>
                  </div>
                  <div className="flex-1 grid grid-cols-3 gap-4">
                    <div className="text-center">
                      <div className="text-lg font-semibold">{agility.totalAssets}</div>
                      <div className="text-xs text-muted-foreground">Total Assets</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-green-500">{agility.configurableCount}</div>
                      <div className="text-xs text-muted-foreground">Configurable</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-red-500">{agility.hardcodedCount}</div>
                      <div className="text-xs text-muted-foreground">Hardcoded</div>
                    </div>
                  </div>
                </div>
                {agility.recommendations.length > 0 && (
                  <div className="space-y-2">
                    {agility.recommendations.map((rec, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        <AlertTriangle className="h-4 w-4 mt-0.5 text-yellow-500 shrink-0" />
                        <span className="text-muted-foreground">{rec}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Crypto Inventory Tab ──────────────────────────────── */}
        <TabsContent value="inventory" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by name, hostname, or service..."
                className="pl-9"
                value={inventorySearch}
                onChange={(e) => setInventorySearch(e.target.value)}
              />
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risks</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="safe">Safe</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sourceFilter} onValueChange={setSourceFilter}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Source" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sources</SelectItem>
                <SelectItem value="tls_certificate">TLS Certificate</SelectItem>
                <SelectItem value="ssh_key">SSH Key</SelectItem>
                <SelectItem value="vpn_tunnel">VPN Tunnel</SelectItem>
                <SelectItem value="jwt_signing">JWT Signing</SelectItem>
                <SelectItem value="code_signing">Code Signing</SelectItem>
                <SelectItem value="api_key">API Key</SelectItem>
                <SelectItem value="database_encryption">Database Encryption</SelectItem>
                <SelectItem value="manual_entry">Manual Entry</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {inventoryLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : inventory.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Key className="h-10 w-10 text-muted-foreground mb-3" />
                <h3 className="text-sm font-medium mb-1">No cryptographic assets found</h3>
                <p className="text-xs text-muted-foreground max-w-md">
                  Add your organization's cryptographic assets to begin quantum vulnerability assessment. Include TLS
                  certificates, SSH keys, VPN configurations, and code signing keys.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {inventory.map((asset) => (
                <Card key={asset.id}>
                  <CardContent className="py-3">
                    <div className="flex items-center gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium truncate">{asset.assetName}</span>
                          <Badge variant="outline" className={riskColor(asset.quantumRiskLevel)}>
                            {asset.quantumRiskLevel}
                          </Badge>
                          {asset.isQuantumVulnerable && (
                            <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
                              Quantum Vulnerable
                            </Badge>
                          )}
                          {asset.isHardcoded && (
                            <Badge variant="outline" className="bg-slate-500/10 text-slate-500">
                              Hardcoded
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span className="font-mono">
                            {asset.algorithm}
                            {asset.keyLength ? ` (${asset.keyLength}-bit)` : ""}
                          </span>
                          <span>{sourceLabel(asset.source)}</span>
                          {asset.hostname && (
                            <span>
                              {asset.hostname}
                              {asset.port ? `:${asset.port}` : ""}
                            </span>
                          )}
                          {asset.serviceName && <span>{asset.serviceName}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        {asset.pqcReplacement && (
                          <div className="text-right">
                            <div className="text-xs text-muted-foreground">Recommended</div>
                            <div className="text-xs font-medium text-green-500">{asset.pqcReplacement}</div>
                          </div>
                        )}
                        <Badge variant="outline" className={statusColor(asset.migrationStatus)}>
                          {asset.migrationStatus.replace(/_/g, " ")}
                        </Badge>
                        <Select
                          value={asset.migrationStatus}
                          onValueChange={(val) => updateAssetMutation.mutate({ id: asset.id, migrationStatus: val })}
                        >
                          <SelectTrigger className="w-[130px] h-8 text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="not_started">Not Started</SelectItem>
                            <SelectItem value="assessed">Assessed</SelectItem>
                            <SelectItem value="planned">Planned</SelectItem>
                            <SelectItem value="in_progress">In Progress</SelectItem>
                            <SelectItem value="migrated">Migrated</SelectItem>
                            <SelectItem value="verified">Verified</SelectItem>
                            <SelectItem value="deferred">Deferred</SelectItem>
                          </SelectContent>
                        </Select>
                        <Button variant="ghost" size="sm" onClick={() => deleteAssetMutation.mutate(asset.id)}>
                          <Trash2 className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Migration Roadmap Tab ─────────────────────────────── */}
        <TabsContent value="roadmap" className="space-y-6">
          {phases.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Shield className="h-10 w-10 text-green-500 mb-3" />
                <h3 className="text-sm font-medium mb-1">No quantum-vulnerable assets</h3>
                <p className="text-xs text-muted-foreground max-w-md">
                  All cryptographic assets in your inventory are quantum-safe, or no vulnerable assets have been
                  registered yet.
                </p>
              </CardContent>
            </Card>
          ) : (
            phases.map((phase) => (
              <Card key={phase.phase}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base">
                        Phase {phase.phase}: {phase.phaseName}
                      </CardTitle>
                      <CardDescription className="mt-1">{phase.description}</CardDescription>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-semibold">{phase.estimatedWeeks} weeks</div>
                      <div className="text-xs text-muted-foreground">{phase.assets.length} assets</div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {phase.assets.map((asset) => (
                      <div key={asset.id} className="flex items-center gap-3 py-2 border-b last:border-0">
                        <Lock className="h-4 w-4 text-muted-foreground shrink-0" />
                        <span className="text-sm font-medium flex-1">{asset.assetName}</span>
                        <span className="text-xs font-mono text-red-500">{asset.algorithm}</span>
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs font-mono text-green-500">{asset.replacement}</span>
                        <Badge variant="outline" className="text-xs">
                          Priority {asset.priority}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* ── Migration Tasks Tab ──────────────────────────────── */}
        <TabsContent value="tasks" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {tasks.length} migration task{tasks.length !== 1 ? "s" : ""} (
              {tasks.filter((t) => t.status === "verified").length} completed)
            </p>
            <Dialog open={addTaskOpen} onOpenChange={setAddTaskOpen}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" />
                  Add Task
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Create Migration Task</DialogTitle>
                  <DialogDescription>
                    Track a cryptographic migration from a vulnerable algorithm to a post-quantum replacement
                  </DialogDescription>
                </DialogHeader>
                <AddTaskForm onSubmit={(data) => addTaskMutation.mutate(data)} isPending={addTaskMutation.isPending} />
              </DialogContent>
            </Dialog>
          </div>

          {tasks.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <FileText className="h-10 w-10 text-muted-foreground mb-3" />
                <h3 className="text-sm font-medium mb-1">No migration tasks</h3>
                <p className="text-xs text-muted-foreground max-w-md">
                  Create migration tasks to track the progress of upgrading from vulnerable algorithms to post-quantum
                  alternatives.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {tasks.map((task) => (
                <Card key={task.id}>
                  <CardContent className="py-3">
                    <div className="flex items-center gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium">{task.title}</span>
                          <Badge variant="outline" className={statusColor(task.status)}>
                            {task.status.replace(/_/g, " ")}
                          </Badge>
                          <Badge variant="outline" className={riskColor(task.priority)}>
                            {task.priority}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span className="font-mono">
                            {task.currentAlgorithm} → {task.targetAlgorithm}
                          </span>
                          {task.nistStandard && <span>{task.nistStandard}</span>}
                          {task.assignedTo && <span>Assigned: {task.assignedTo}</span>}
                          {task.effortEstimateDays && <span>{task.effortEstimateDays}d effort</span>}
                          {task.dueDate && <span>Due: {formatDate(task.dueDate)}</span>}
                        </div>
                        {task.description && <p className="text-xs text-muted-foreground mt-1">{task.description}</p>}
                        {task.blockers && <p className="text-xs text-red-500 mt-1">Blocked: {task.blockers}</p>}
                      </div>
                      <Select
                        value={task.status}
                        onValueChange={(val) => updateTaskMutation.mutate({ id: task.id, status: val })}
                      >
                        <SelectTrigger className="w-[130px] h-8 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="not_started">Not Started</SelectItem>
                          <SelectItem value="assessed">Assessed</SelectItem>
                          <SelectItem value="planned">Planned</SelectItem>
                          <SelectItem value="in_progress">In Progress</SelectItem>
                          <SelectItem value="migrated">Migrated</SelectItem>
                          <SelectItem value="verified">Verified</SelectItem>
                          <SelectItem value="deferred">Deferred</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── NIST PQC Compliance Tab ──────────────────────────── */}
        <TabsContent value="nist" className="space-y-6">
          {nistCompliance &&
            Object.entries(nistCompliance).map(([key, std]) => (
              <Card key={key}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base">
                        {std.standard} — {std.name}
                      </CardTitle>
                      <CardDescription className="mt-1">{std.description}</CardDescription>
                    </div>
                    <Badge
                      variant="outline"
                      className={
                        std.status === "compliant"
                          ? "bg-green-500/10 text-green-500 border-green-500/20"
                          : std.status === "in_progress"
                            ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
                            : "bg-slate-500/10 text-slate-500 border-slate-500/20"
                      }
                    >
                      {std.status === "compliant"
                        ? "Compliant"
                        : std.status === "in_progress"
                          ? "In Progress"
                          : "Not Started"}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-6">
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Migration Progress</span>
                        <span className={`text-sm font-semibold ${scoreColor(std.progress)}`}>{std.progress}%</span>
                      </div>
                      <Progress value={std.progress} className="h-2" />
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold">{std.relevantAssets}</div>
                      <div className="text-xs text-muted-foreground">Need Migration</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-green-500">{std.migratedAssets}</div>
                      <div className="text-xs text-muted-foreground">Migrated</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
        </TabsContent>

        {/* ── Algorithm Agility Tab ────────────────────────────── */}
        <TabsContent value="agility" className="space-y-6">
          {agility && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-center gap-2 mb-1">
                      <TrendingUp className="h-4 w-4 text-muted-foreground" />
                      <span className="text-xs text-muted-foreground">Agility Score</span>
                    </div>
                    <div className={`text-2xl font-semibold ${scoreColor(agility.agilityScore)}`}>
                      {agility.agilityScore}%
                    </div>
                    <Progress value={agility.agilityScore} className="h-1.5 mt-2" />
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-center gap-2 mb-1">
                      <ShieldCheck className="h-4 w-4 text-green-500" />
                      <span className="text-xs text-muted-foreground">Configurable</span>
                    </div>
                    <div className="text-2xl font-semibold text-green-500">{agility.configurableCount}</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      algorithms can be swapped without code changes
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-center gap-2 mb-1">
                      <XCircle className="h-4 w-4 text-red-500" />
                      <span className="text-xs text-muted-foreground">Hardcoded</span>
                    </div>
                    <div className="text-2xl font-semibold text-red-500">{agility.hardcodedCount}</div>
                    <div className="text-xs text-muted-foreground mt-1">require code changes to upgrade</div>
                  </CardContent>
                </Card>
              </div>

              {/* Recommendations */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Recommendations</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {agility.recommendations.map((rec, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <ChevronRight className="h-4 w-4 mt-0.5 text-blue-500 shrink-0" />
                      <span className="text-sm">{rec}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>

              {/* Hardcoded Assets */}
              {agility.hardcodedAssets.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Hardcoded Cryptographic Assets</CardTitle>
                    <CardDescription>
                      These assets use hardcoded algorithms that cannot be upgraded without code changes
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {agility.hardcodedAssets.map((asset) => (
                        <div key={asset.id} className="flex items-center gap-3 py-2 border-b last:border-0">
                          <Lock className="h-4 w-4 text-red-500 shrink-0" />
                          <span className="text-sm font-medium flex-1">{asset.assetName}</span>
                          <span className="text-xs font-mono">{asset.algorithm}</span>
                          <span className="text-xs text-muted-foreground">{sourceLabel(asset.source)}</span>
                          {asset.filePath && (
                            <span className="text-xs font-mono text-muted-foreground">{asset.filePath}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Add Asset Form ────────────────────────────────────────────────

function AddAssetForm({
  onSubmit,
  isPending,
  enums,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
  enums?: DashboardData["enums"];
}) {
  const [assetName, setAssetName] = useState("");
  const [algorithm, setAlgorithm] = useState("");
  const [keyLength, setKeyLength] = useState("");
  const [source, setSource] = useState("");
  const [hostname, setHostname] = useState("");
  const [port, setPort] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [isHardcoded, setIsHardcoded] = useState("false");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const data: Record<string, unknown> = {
      assetName,
      algorithm,
      source,
      isHardcoded: isHardcoded === "true",
    };
    if (keyLength) data.keyLength = Number(keyLength);
    if (hostname) data.hostname = hostname;
    if (port) data.port = Number(port);
    if (serviceName) data.serviceName = serviceName;
    onSubmit(data);
  };

  const algorithmOptions =
    enums?.algorithmTypes ||
    ALGORITHM_CATEGORIES.asymmetric.concat(
      ALGORITHM_CATEGORIES.symmetric,
      ALGORITHM_CATEGORIES.hash,
      ALGORITHM_CATEGORIES.pqc,
    );
  const sourceOptions = enums?.assetSources || [
    "tls_certificate",
    "ssh_key",
    "api_key",
    "vpn_tunnel",
    "code_signing",
    "database_encryption",
    "jwt_signing",
    "manual_entry",
  ];

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label>Asset Name *</Label>
        <Input
          placeholder="e.g., Production TLS Certificate"
          value={assetName}
          onChange={(e) => setAssetName(e.target.value)}
          required
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Algorithm *</Label>
          <Select value={algorithm} onValueChange={setAlgorithm} required>
            <SelectTrigger>
              <SelectValue placeholder="Select algorithm" />
            </SelectTrigger>
            <SelectContent>
              {algorithmOptions.map((algo) => (
                <SelectItem key={algo} value={algo}>
                  {algo}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Key Length (bits)</Label>
          <Input
            type="number"
            placeholder="e.g., 2048"
            value={keyLength}
            onChange={(e) => setKeyLength(e.target.value)}
          />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Source *</Label>
          <Select value={source} onValueChange={setSource} required>
            <SelectTrigger>
              <SelectValue placeholder="Select source" />
            </SelectTrigger>
            <SelectContent>
              {sourceOptions.map((s) => (
                <SelectItem key={s} value={s}>
                  {sourceLabel(s)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Hardcoded?</Label>
          <Select value={isHardcoded} onValueChange={setIsHardcoded}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="false">No (Configurable)</SelectItem>
              <SelectItem value="true">Yes (Hardcoded)</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Hostname</Label>
          <Input placeholder="e.g., api.example.com" value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Port</Label>
          <Input type="number" placeholder="e.g., 443" value={port} onChange={(e) => setPort(e.target.value)} />
        </div>
      </div>
      <div className="space-y-2">
        <Label>Service Name</Label>
        <Input
          placeholder="e.g., Production API Gateway"
          value={serviceName}
          onChange={(e) => setServiceName(e.target.value)}
        />
      </div>
      <DialogFooter>
        <Button type="submit" disabled={isPending || !assetName || !algorithm || !source}>
          {isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
          Add Asset
        </Button>
      </DialogFooter>
    </form>
  );
}

// ── Add Task Form ─────────────────────────────────────────────────

function AddTaskForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [currentAlgorithm, setCurrentAlgorithm] = useState("");
  const [targetAlgorithm, setTargetAlgorithm] = useState("");
  const [priority, setPriority] = useState("medium");
  const [assignedTo, setAssignedTo] = useState("");
  const [effortDays, setEffortDays] = useState("");
  const [nistStandard, setNistStandard] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const data: Record<string, unknown> = {
      title,
      currentAlgorithm,
      targetAlgorithm,
      priority,
    };
    if (description) data.description = description;
    if (assignedTo) data.assignedTo = assignedTo;
    if (effortDays) data.effortEstimateDays = Number(effortDays);
    if (nistStandard) data.nistStandard = nistStandard;
    onSubmit(data);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label>Task Title *</Label>
        <Input
          placeholder="e.g., Migrate API Gateway TLS to ML-KEM"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          required
        />
      </div>
      <div className="space-y-2">
        <Label>Description</Label>
        <Textarea
          placeholder="Detailed description of the migration task..."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={2}
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Current Algorithm *</Label>
          <Input
            placeholder="e.g., RSA-2048"
            value={currentAlgorithm}
            onChange={(e) => setCurrentAlgorithm(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label>Target Algorithm *</Label>
          <Input
            placeholder="e.g., CRYSTALS-Kyber"
            value={targetAlgorithm}
            onChange={(e) => setTargetAlgorithm(e.target.value)}
            required
          />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>Priority</Label>
          <Select value={priority} onValueChange={setPriority}>
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
        <div className="space-y-2">
          <Label>Effort (days)</Label>
          <Input
            type="number"
            placeholder="e.g., 14"
            value={effortDays}
            onChange={(e) => setEffortDays(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label>NIST Standard</Label>
          <Select value={nistStandard} onValueChange={setNistStandard}>
            <SelectTrigger>
              <SelectValue placeholder="Select" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="FIPS-203">FIPS-203 (ML-KEM)</SelectItem>
              <SelectItem value="FIPS-204">FIPS-204 (ML-DSA)</SelectItem>
              <SelectItem value="FIPS-205">FIPS-205 (SLH-DSA)</SelectItem>
              <SelectItem value="FIPS-206">FIPS-206 (FN-DSA)</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-2">
        <Label>Assigned To</Label>
        <Input
          placeholder="e.g., security-team@company.com"
          value={assignedTo}
          onChange={(e) => setAssignedTo(e.target.value)}
        />
      </div>
      <DialogFooter>
        <Button type="submit" disabled={isPending || !title || !currentAlgorithm || !targetAlgorithm}>
          {isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
          Create Task
        </Button>
      </DialogFooter>
    </form>
  );
}
