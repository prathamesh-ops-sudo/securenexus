import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  ShieldAlert,
  Shield,
  AlertTriangle,
  Power,
  PowerOff,
  FileWarning,
  Search,
  Plus,
  Trash2,
  RefreshCw,
  Zap,
  Lock,
  Database,
  Clock,
  CheckCircle2,
  XCircle,
  Activity,
  BookOpen,
  Users,
  Target,
  Skull,
  HardDrive,
  Play,
  RotateCcw,
  Download,
  Eye,
  AlertOctagon,
  Plug,
} from "lucide-react";
import { EmptyState } from "@/components/empty-state";

// ─── Types ──────────────────────────────────────────────────────────────────

interface KillSwitchEvent {
  id: string;
  status: string;
  triggeredBy: string;
  triggeredByName: string | null;
  reason: string | null;
  totalSensors: number;
  isolatedCount: number;
  failedCount: number;
  skippedCount: number;
  rollbackAt: string | null;
  rollbackBy: string | null;
  completedAt: string | null;
  incidentId: string | null;
  createdAt: string;
}

interface CanaryFile {
  id: string;
  fileName: string;
  filePath: string;
  fileType: string;
  fileHash: string;
  deployedToHost: string | null;
  status: string;
  triggeredAt: string | null;
  triggerType: string | null;
  alertSent: boolean;
  createdAt: string;
}

interface CanaryTemplate {
  fileName: string;
  fileType: string;
  description: string;
  contentHint: string;
}

interface RansomwareGroup {
  id: string;
  name: string;
  aliases: string[] | null;
  threatLevel: string;
  isActive: boolean;
  firstSeen: string | null;
  lastActive: string | null;
  description: string | null;
  ttps: { id: string; name: string; tactic: string }[] | null;
  targetIndustries: string[] | null;
  targetRegions: string[] | null;
  ransomwareVariants: { name: string; type: string }[] | null;
  knownPaymentAddresses: { currency: string; address: string }[] | null;
  avgRansomDemandUsd: number | null;
  decryptorAvailable: boolean;
  decryptorSource: string | null;
  iocIndicators: { type: string; value: string }[] | null;
  referenceUrls: string[] | null;
  createdAt: string;
}

interface RecoveryRunbook {
  id: string;
  title: string;
  incidentId: string | null;
  status: string;
  scenario: string;
  affectedSystems: string[] | null;
  affectedDataTypes: string[] | null;
  ransomwareVariant: string | null;
  estimatedDowntimeHours: number | null;
  estimatedRecoveryCostUsd: number | null;
  steps:
    | {
        order: number;
        title: string;
        description: string;
        responsible: string;
        estimatedMinutes: number;
        status: string;
      }[]
    | null;
  priorityActions: string[] | null;
  communicationPlan: { stakeholder: string; timing: string; channel: string }[] | null;
  legalRequirements: string[] | null;
  generatedBy: string | null;
  createdAt: string;
}

interface TabletopExercise {
  id: string;
  title: string;
  description: string | null;
  status: string;
  scenarioType: string;
  difficulty: string;
  ransomwareGroup: string | null;
  scenario: {
    background: string;
    initialCompromise: string;
    escalation: string;
    impact: string;
    objectives: string[];
  } | null;
  injects: { order: number; timeMinutes: number; description: string; expectedResponse: string; hint: string }[] | null;
  participants: unknown[] | null;
  findings: unknown[] | null;
  score: number | null;
  scheduledAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  durationMinutes: number | null;
  createdAt: string;
}

interface TabletopTemplate {
  title: string;
  scenarioType: string;
  difficulty: string;
  description: string;
  durationMinutes: number;
}

interface BackupVerification {
  id: string;
  backupName: string;
  backupType: string;
  backupLocation: string;
  status: string;
  integrityCheckResult: string | null;
  restoreTestResult: string | null;
  backupSizeBytes: number | null;
  encryptionStatus: string | null;
  lastVerifiedAt: string | null;
  nextScheduledVerification: string | null;
  verificationDurationSeconds: number | null;
  issues: { type: string; description: string; severity: string }[] | null;
  coveredSystems: string[] | null;
  rpoHours: number | null;
  rtoHours: number | null;
  createdAt: string;
}

interface DefenseSummary {
  killSwitch: { totalEvents: number; lastEvent: KillSwitchEvent | null };
  canaryFiles: { total: number; active: number; triggered: number };
  ransomwareGroups: { tracked: number };
  recoveryRunbooks: { total: number };
  tabletopExercises: { total: number; completed: number; lastCompleted: TabletopExercise | null };
  backupVerifications: { total: number; passed: number; failed: number };
  readiness: { score: number; grade: string; recommendations: string[] };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function apiFetch(url: string, options?: RequestInit) {
  const res = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: `API error: ${res.status}` }));
    throw new Error(body.message || `API error: ${res.status}`);
  }
  return res.json();
}

function formatDate(d: string | null | undefined): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatUsd(amount: number | null | undefined): string {
  if (amount == null) return "—";
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(
    amount,
  );
}

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const statusColors: Record<string, string> = {
  active: "bg-green-500/20 text-green-400 border-green-500/30",
  triggered: "bg-red-500/20 text-red-400 border-red-500/30",
  disabled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  completed: "bg-green-500/20 text-green-400 border-green-500/30",
  in_progress: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  initiated: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  partial_failure: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  failed: "bg-red-500/20 text-red-400 border-red-500/30",
  rolled_back: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  passed: "bg-green-500/20 text-green-400 border-green-500/30",
  pending: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  draft: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  scheduled: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  generated: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  reviewed: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  approved: "bg-green-500/20 text-green-400 border-green-500/30",
  executed: "bg-teal-500/20 text-teal-400 border-teal-500/30",
  cancelled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

function gradeColor(grade: string): string {
  if (grade === "A") return "text-green-400";
  if (grade === "B") return "text-blue-400";
  if (grade === "C") return "text-yellow-400";
  if (grade === "D") return "text-orange-400";
  return "text-red-400";
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function RansomwareDefensePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("dashboard");

  // Kill switch
  const [killSwitchOpen, setKillSwitchOpen] = useState(false);
  const [killSwitchReason, setKillSwitchReason] = useState("");
  const [killSwitchIncident, setKillSwitchIncident] = useState("");

  // Canary files
  const [canaryDeployOpen, setCanaryDeployOpen] = useState(false);
  const [canaryFileName, setCanaryFileName] = useState("");
  const [canaryFilePath, setCanaryFilePath] = useState("");
  const [canaryFileType, setCanaryFileType] = useState("xlsx");
  const [canaryHost, setCanaryHost] = useState("");
  const [canaryTemplateOpen, setCanaryTemplateOpen] = useState(false);
  const [canaryTemplatePath, setCanaryTemplatePath] = useState("");
  const [canaryTemplateHost, setCanaryTemplateHost] = useState("");

  // Runbook
  const [runbookOpen, setRunbookOpen] = useState(false);
  const [runbookScenario, setRunbookScenario] = useState("");
  const [runbookSystems, setRunbookSystems] = useState("");
  const [runbookDataTypes, setRunbookDataTypes] = useState("");
  const [runbookVariant, setRunbookVariant] = useState("");
  const [selectedRunbook, setSelectedRunbook] = useState<RecoveryRunbook | null>(null);

  // Exercise
  const [exerciseOpen, setExerciseOpen] = useState(false);
  const [exerciseTitle, setExerciseTitle] = useState("");
  const [exerciseType, setExerciseType] = useState("ransomware");
  const [exerciseDifficulty, setExerciseDifficulty] = useState("intermediate");
  const [selectedExercise, setSelectedExercise] = useState<TabletopExercise | null>(null);

  // Backup
  const [backupOpen, setBackupOpen] = useState(false);
  const [backupName, setBackupName] = useState("");
  const [backupType, setBackupType] = useState("full");
  const [backupLocation, setBackupLocation] = useState("");
  const [backupEncryption, setBackupEncryption] = useState("encrypted");

  // Group detail
  const [selectedGroup, setSelectedGroup] = useState<RansomwareGroup | null>(null);

  // ── Queries ─────────────────────────────────────────────────────────────

  const { data: summary } = useQuery<DefenseSummary>({
    queryKey: ["/api/ransomware-defense/summary"],
    queryFn: () => apiFetch("/api/ransomware-defense/summary"),
  });

  const { data: killSwitchEvents } = useQuery<KillSwitchEvent[]>({
    queryKey: ["/api/ransomware-defense/kill-switch"],
    queryFn: () => apiFetch("/api/ransomware-defense/kill-switch"),
  });

  const { data: canaryFiles } = useQuery<CanaryFile[]>({
    queryKey: ["/api/ransomware-defense/canary-files"],
    queryFn: () => apiFetch("/api/ransomware-defense/canary-files"),
  });

  const { data: canaryTemplates } = useQuery<CanaryTemplate[]>({
    queryKey: ["/api/ransomware-defense/canary-files/templates"],
    queryFn: () => apiFetch("/api/ransomware-defense/canary-files/templates"),
  });

  const { data: groupsData } = useQuery<{ groups: RansomwareGroup[]; seedGroups: unknown[] }>({
    queryKey: ["/api/ransomware-defense/groups"],
    queryFn: () => apiFetch("/api/ransomware-defense/groups"),
  });

  const { data: runbooks } = useQuery<RecoveryRunbook[]>({
    queryKey: ["/api/ransomware-defense/runbooks"],
    queryFn: () => apiFetch("/api/ransomware-defense/runbooks"),
  });

  const { data: exercises } = useQuery<TabletopExercise[]>({
    queryKey: ["/api/ransomware-defense/exercises"],
    queryFn: () => apiFetch("/api/ransomware-defense/exercises"),
  });

  const { data: exerciseTemplates } = useQuery<TabletopTemplate[]>({
    queryKey: ["/api/ransomware-defense/exercises/templates"],
    queryFn: () => apiFetch("/api/ransomware-defense/exercises/templates"),
  });

  const { data: backups } = useQuery<BackupVerification[]>({
    queryKey: ["/api/ransomware-defense/backups"],
    queryFn: () => apiFetch("/api/ransomware-defense/backups"),
  });

  // ── Mutations ───────────────────────────────────────────────────────────

  const activateKillSwitch = useMutation({
    mutationFn: (data: { reason: string; incidentId?: string }) =>
      apiFetch("/api/ransomware-defense/kill-switch/activate", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Kill Switch Activated", description: result.message });
      setKillSwitchOpen(false);
      setKillSwitchReason("");
      setKillSwitchIncident("");
    },
    onError: (err: Error) => {
      toast({ title: "Kill switch failed", description: err.message, variant: "destructive" });
    },
  });

  const rollbackKillSwitch = useMutation({
    mutationFn: (eventId: string) =>
      apiFetch(`/api/ransomware-defense/kill-switch/rollback/${eventId}`, { method: "POST" }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Kill Switch Rolled Back", description: result.message });
    },
    onError: (err: Error) => {
      toast({ title: "Rollback failed", description: err.message, variant: "destructive" });
    },
  });

  const deployCanary = useMutation({
    mutationFn: (data: { fileName: string; filePath: string; fileType: string; deployedToHost?: string }) =>
      apiFetch("/api/ransomware-defense/canary-files", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Canary file deployed" });
      setCanaryDeployOpen(false);
      setCanaryFileName("");
      setCanaryFilePath("");
      setCanaryHost("");
    },
    onError: (err: Error) => {
      toast({ title: "Deploy failed", description: err.message, variant: "destructive" });
    },
  });

  const deployCanaryTemplates = useMutation({
    mutationFn: (data: { deployPath: string; hostName?: string }) =>
      apiFetch("/api/ransomware-defense/canary-files/deploy-templates", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Canary templates deployed", description: result.message });
      setCanaryTemplateOpen(false);
      setCanaryTemplatePath("");
      setCanaryTemplateHost("");
    },
    onError: (err: Error) => {
      toast({ title: "Deploy failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteCanary = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/ransomware-defense/canary-files/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Canary file removed" });
    },
  });

  const importSeedGroups = useMutation({
    mutationFn: () => apiFetch("/api/ransomware-defense/groups/import-seed", { method: "POST" }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Groups imported", description: result.message });
    },
    onError: (err: Error) => {
      toast({ title: "Import failed", description: err.message, variant: "destructive" });
    },
  });

  const generateRunbook = useMutation({
    mutationFn: (data: {
      scenario: string;
      affectedSystems: string[];
      affectedDataTypes: string[];
      ransomwareVariant?: string;
    }) => apiFetch("/api/ransomware-defense/runbooks/generate", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Recovery runbook generated" });
      setRunbookOpen(false);
      setSelectedRunbook(result);
      setRunbookScenario("");
      setRunbookSystems("");
      setRunbookDataTypes("");
      setRunbookVariant("");
    },
    onError: (err: Error) => {
      toast({ title: "Generation failed", description: err.message, variant: "destructive" });
    },
  });

  const createExercise = useMutation({
    mutationFn: (data: { title?: string; scenarioType: string; difficulty: string; templateIndex?: number }) =>
      apiFetch("/api/ransomware-defense/exercises", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Exercise created" });
      setExerciseOpen(false);
      setSelectedExercise(result);
      setExerciseTitle("");
    },
    onError: (err: Error) => {
      toast({ title: "Creation failed", description: err.message, variant: "destructive" });
    },
  });

  const updateExercise = useMutation({
    mutationFn: ({ id, ...data }: { id: string; status?: string; score?: number }) =>
      apiFetch(`/api/ransomware-defense/exercises/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Exercise updated" });
    },
  });

  const deleteExercise = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/ransomware-defense/exercises/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Exercise deleted" });
      setSelectedExercise(null);
    },
  });

  const registerBackup = useMutation({
    mutationFn: (data: { backupName: string; backupType: string; backupLocation: string; encryptionStatus: string }) =>
      apiFetch("/api/ransomware-defense/backups", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Backup registered" });
      setBackupOpen(false);
      setBackupName("");
      setBackupLocation("");
    },
    onError: (err: Error) => {
      toast({ title: "Registration failed", description: err.message, variant: "destructive" });
    },
  });

  const verifyBackup = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/ransomware-defense/backups/${id}/verify`, { method: "POST" }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      const issues = result.verification?.issues?.length || 0;
      toast({
        title: `Verification ${result.verification?.result}`,
        description: issues > 0 ? `${issues} issue(s) found` : "All checks passed",
      });
    },
    onError: (err: Error) => {
      toast({ title: "Verification failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteBackup = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/ransomware-defense/backups/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ransomware-defense"] });
      toast({ title: "Backup removed" });
    },
  });

  // ── Render ──────────────────────────────────────────────────────────────

  const readiness = summary?.readiness;
  const groups = groupsData?.groups || [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-red-400" />
            Ransomware Defense Suite
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Kill switch, canary files, ransomware intelligence, recovery runbooks, tabletop exercises, backup
            verification
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
            onClick={() => importSeedGroups.mutate()}
            disabled={importSeedGroups.isPending}
          >
            <Download className="h-4 w-4" />
            Import Intel
          </Button>
          <Button className="gap-1.5 bg-red-600 hover:bg-red-700 text-white" onClick={() => setKillSwitchOpen(true)}>
            <Power className="h-4 w-4" />
            Kill Switch
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-900/70 border border-zinc-800">
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="killswitch">Kill Switch</TabsTrigger>
          <TabsTrigger value="canary">Canary Files</TabsTrigger>
          <TabsTrigger value="intelligence">Intelligence</TabsTrigger>
          <TabsTrigger value="runbooks">Recovery</TabsTrigger>
          <TabsTrigger value="exercises">Tabletop</TabsTrigger>
          <TabsTrigger value="backups">Backups</TabsTrigger>
        </TabsList>

        {/* ── DASHBOARD TAB ────────────────────────────────────────────── */}
        <TabsContent value="dashboard" className="space-y-6">
          {/* Readiness Score */}
          {readiness && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Ransomware Readiness Score
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-6">
                  <div className="text-center">
                    <div className={`text-5xl font-bold ${gradeColor(readiness.grade)}`}>{readiness.grade}</div>
                    <div className="text-sm text-zinc-400 mt-1">{readiness.score}/100</div>
                  </div>
                  <div className="flex-1">
                    <Progress value={readiness.score} className="h-3 mb-3" />
                    {readiness.recommendations.length > 0 && (
                      <div className="space-y-1">
                        <p className="text-xs font-medium text-zinc-400">Recommendations:</p>
                        {readiness.recommendations.map((r, i) => (
                          <p key={i} className="text-xs text-zinc-500 flex items-start gap-1">
                            <AlertTriangle className="h-3 w-3 text-yellow-400 mt-0.5 shrink-0" />
                            {r}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3 text-center">
                <Power className="h-5 w-5 mx-auto text-red-400 mb-1" />
                <div className="text-2xl font-bold">{summary?.killSwitch.totalEvents ?? 0}</div>
                <div className="text-xs text-zinc-400">Kill Switch Events</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3 text-center">
                <FileWarning className="h-5 w-5 mx-auto text-amber-400 mb-1" />
                <div className="text-2xl font-bold">{summary?.canaryFiles.active ?? 0}</div>
                <div className="text-xs text-zinc-400">Active Canaries</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3 text-center">
                <AlertOctagon className="h-5 w-5 mx-auto text-red-400 mb-1" />
                <div className="text-2xl font-bold">{summary?.canaryFiles.triggered ?? 0}</div>
                <div className="text-xs text-zinc-400">Triggered Canaries</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3 text-center">
                <Skull className="h-5 w-5 mx-auto text-purple-400 mb-1" />
                <div className="text-2xl font-bold">{summary?.ransomwareGroups.tracked ?? 0}</div>
                <div className="text-xs text-zinc-400">Groups Tracked</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3 text-center">
                <BookOpen className="h-5 w-5 mx-auto text-blue-400 mb-1" />
                <div className="text-2xl font-bold">{summary?.recoveryRunbooks.total ?? 0}</div>
                <div className="text-xs text-zinc-400">Recovery Runbooks</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3 text-center">
                <HardDrive className="h-5 w-5 mx-auto text-green-400 mb-1" />
                <div className="text-2xl font-bold">
                  {summary?.backupVerifications.passed ?? 0}/{summary?.backupVerifications.total ?? 0}
                </div>
                <div className="text-xs text-zinc-400">Backups Verified</div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Events */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Recent Kill Switch Events</CardTitle>
              </CardHeader>
              <CardContent>
                {killSwitchEvents && killSwitchEvents.length > 0 ? (
                  <div className="space-y-2">
                    {killSwitchEvents.slice(0, 5).map((e) => (
                      <div
                        key={e.id}
                        className="flex items-center justify-between text-sm border border-zinc-800 rounded p-2"
                      >
                        <div>
                          <Badge className={statusColors[e.status] || "bg-zinc-700 text-zinc-300"}>
                            {e.status.replace("_", " ")}
                          </Badge>
                          <span className="text-zinc-400 ml-2 text-xs">
                            {e.isolatedCount}/{e.totalSensors} isolated
                          </span>
                        </div>
                        <span className="text-xs text-zinc-500">{formatDate(e.createdAt)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    icon={Power}
                    title="No kill switch events"
                    description="The emergency kill switch has not been activated. It will instantly isolate all endpoints when active ransomware encryption is detected."
                    compact
                  />
                )}
              </CardContent>
            </Card>

            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Tabletop Exercises</CardTitle>
              </CardHeader>
              <CardContent>
                {exercises && exercises.length > 0 ? (
                  <div className="space-y-2">
                    {exercises.slice(0, 5).map((e) => (
                      <div
                        key={e.id}
                        className="flex items-center justify-between text-sm border border-zinc-800 rounded p-2"
                      >
                        <div>
                          <span className="text-zinc-300">{e.title}</span>
                          <Badge className={`ml-2 ${statusColors[e.status] || "bg-zinc-700"}`}>{e.status}</Badge>
                        </div>
                        <span className="text-xs text-zinc-500">{formatDate(e.createdAt)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    icon={Users}
                    title="No tabletop exercises yet"
                    description="Simulate ransomware attacks to train your team. Create exercises from templates or build custom scenarios."
                    compact
                  />
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── KILL SWITCH TAB ──────────────────────────────────────────── */}
        <TabsContent value="killswitch" className="space-y-6">
          <Card className="bg-zinc-900/50 border-zinc-800 border-red-500/30">
            <CardContent className="p-8 text-center">
              <Power className="h-16 w-16 mx-auto text-red-400 mb-4" />
              <h2 className="text-xl font-bold text-zinc-200 mb-2">Emergency Kill Switch</h2>
              <p className="text-sm text-zinc-400 mb-4 max-w-lg mx-auto">
                Instantly isolate all endpoints in your organization. This creates isolate_host response actions for
                every active sensor. Use this when active ransomware encryption is detected.
              </p>
              <Button
                size="lg"
                className="bg-red-600 hover:bg-red-700 text-white gap-2 text-lg px-8 py-6"
                onClick={() => setKillSwitchOpen(true)}
              >
                <Power className="h-5 w-5" />
                ISOLATE ALL ENDPOINTS
              </Button>
            </CardContent>
          </Card>

          {/* Kill Switch History */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-sm font-medium text-zinc-400">Kill Switch History</CardTitle>
            </CardHeader>
            <CardContent>
              {killSwitchEvents && killSwitchEvents.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">Triggered By</TableHead>
                      <TableHead className="text-zinc-400">Reason</TableHead>
                      <TableHead className="text-zinc-400">Sensors</TableHead>
                      <TableHead className="text-zinc-400">Isolated</TableHead>
                      <TableHead className="text-zinc-400">Failed</TableHead>
                      <TableHead className="text-zinc-400">Time</TableHead>
                      <TableHead className="text-zinc-400">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {killSwitchEvents.map((e) => (
                      <TableRow key={e.id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell>
                          <Badge className={statusColors[e.status] || "bg-zinc-700"}>
                            {e.status.replace("_", " ")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-zinc-300">{e.triggeredByName || "System"}</TableCell>
                        <TableCell className="text-zinc-400 max-w-[200px] truncate">{e.reason || "—"}</TableCell>
                        <TableCell>{e.totalSensors}</TableCell>
                        <TableCell className="text-green-400">{e.isolatedCount}</TableCell>
                        <TableCell className={e.failedCount > 0 ? "text-red-400" : ""}>{e.failedCount}</TableCell>
                        <TableCell className="text-zinc-500 text-xs">{formatDate(e.createdAt)}</TableCell>
                        <TableCell>
                          {(e.status === "completed" || e.status === "partial_failure") && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="gap-1 border-zinc-700 text-xs"
                              onClick={() => rollbackKillSwitch.mutate(e.id)}
                              disabled={rollbackKillSwitch.isPending}
                            >
                              <RotateCcw className="h-3 w-3" />
                              Rollback
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState
                  icon={Power}
                  title="No kill switch activations"
                  description="The kill switch has not been activated. When triggered, it isolates all endpoints to contain active ransomware encryption."
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── CANARY FILES TAB ─────────────────────────────────────────── */}
        <TabsContent value="canary" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-zinc-200">Canary Files</h2>
              <p className="text-sm text-zinc-400">
                Fake "important" files deployed to critical paths. Any access or encryption triggers an immediate alert.
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
                onClick={() => setCanaryTemplateOpen(true)}
              >
                <Zap className="h-4 w-4" />
                Deploy Templates
              </Button>
              <Button className="gap-1.5" onClick={() => setCanaryDeployOpen(true)}>
                <Plus className="h-4 w-4" />
                Deploy Canary
              </Button>
            </div>
          </div>

          {/* Canary Templates Preview */}
          {canaryTemplates && canaryTemplates.length > 0 && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">
                  Available Templates ({canaryTemplates.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                  {canaryTemplates.map((t, i) => (
                    <div key={i} className="border border-zinc-800 rounded p-2 text-xs">
                      <div className="text-zinc-300 truncate font-medium">{t.fileName}</div>
                      <div className="text-zinc-500 mt-0.5">{t.description}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Active Canary Files */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              {canaryFiles && canaryFiles.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-400">File Name</TableHead>
                      <TableHead className="text-zinc-400">Path</TableHead>
                      <TableHead className="text-zinc-400">Host</TableHead>
                      <TableHead className="text-zinc-400">Type</TableHead>
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">Triggered</TableHead>
                      <TableHead className="text-zinc-400">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {canaryFiles.map((f) => (
                      <TableRow key={f.id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell className="text-zinc-300 font-medium">{f.fileName}</TableCell>
                        <TableCell className="text-zinc-400 text-xs max-w-[200px] truncate">{f.filePath}</TableCell>
                        <TableCell className="text-zinc-400 text-sm">{f.deployedToHost || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {f.fileType}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={statusColors[f.status] || "bg-zinc-700"}>{f.status}</Badge>
                        </TableCell>
                        <TableCell>
                          {f.triggeredAt ? (
                            <div className="text-xs">
                              <span className="text-red-400">{f.triggerType}</span>
                              <br />
                              <span className="text-zinc-500">{formatDate(f.triggeredAt)}</span>
                            </div>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 w-7 p-0 text-zinc-400 hover:text-red-400"
                            onClick={() => deleteCanary.mutate(f.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState
                  icon={FileWarning}
                  title="No canary files deployed"
                  description="Canary files are fake documents placed on critical file shares. Any access or encryption attempt triggers an immediate ransomware alert with zero false positives."
                  action={{
                    label: "Deploy Template Pack",
                    icon: Zap,
                    onClick: () => setCanaryTemplateOpen(true),
                  }}
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── INTELLIGENCE TAB ─────────────────────────────────────────── */}
        <TabsContent value="intelligence" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-zinc-200">Ransomware Group Intelligence</h2>
              <p className="text-sm text-zinc-400">
                Track known ransomware groups, TTPs, payment addresses, decryption key availability
              </p>
            </div>
            <Button
              variant="outline"
              className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
              onClick={() => importSeedGroups.mutate()}
              disabled={importSeedGroups.isPending}
            >
              <Download className="h-4 w-4" />
              Import Seed Data
            </Button>
          </div>

          {groups.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {groups.map((g) => (
                <Card
                  key={g.id}
                  className="bg-zinc-900/50 border-zinc-800 cursor-pointer hover:border-zinc-600 transition-colors"
                  onClick={() => setSelectedGroup(g)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-zinc-200">{g.name}</h3>
                      <Badge className={severityColors[g.threatLevel] || "bg-zinc-700"}>{g.threatLevel}</Badge>
                    </div>
                    <p className="text-xs text-zinc-400 line-clamp-2 mb-3">{g.description}</p>
                    <div className="flex items-center gap-3 text-xs text-zinc-500">
                      <span className="flex items-center gap-1">
                        <Activity className="h-3 w-3" />
                        {g.isActive ? "Active" : "Inactive"}
                      </span>
                      <span className="flex items-center gap-1">
                        <Target className="h-3 w-3" />
                        {(g.ttps as unknown[])?.length || 0} TTPs
                      </span>
                      {g.decryptorAvailable && (
                        <span className="flex items-center gap-1 text-green-400">
                          <Lock className="h-3 w-3" />
                          Decryptor
                        </span>
                      )}
                    </div>
                    {g.avgRansomDemandUsd && (
                      <div className="text-xs text-zinc-500 mt-2">
                        Avg demand: <span className="text-zinc-300">{formatUsd(g.avgRansomDemandUsd)}</span>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent>
                <EmptyState
                  icon={Skull}
                  title="No ransomware groups tracked"
                  description="Import seed data to populate known ransomware groups with their TTPs, payment addresses, and decryptor availability. This powers AI-generated recovery runbooks."
                  action={{
                    label: "Import Known Groups",
                    icon: Download,
                    onClick: () => importSeedGroups.mutate(),
                  }}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── RECOVERY RUNBOOKS TAB ────────────────────────────────────── */}
        <TabsContent value="runbooks" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-zinc-200">Recovery Runbooks</h2>
              <p className="text-sm text-zinc-400">AI-generated step-by-step recovery plans based on attack scenario</p>
            </div>
            <Button className="gap-1.5" onClick={() => setRunbookOpen(true)}>
              <Zap className="h-4 w-4" />
              Generate Runbook
            </Button>
          </div>

          {runbooks && runbooks.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {runbooks.map((r) => (
                <Card
                  key={r.id}
                  className="bg-zinc-900/50 border-zinc-800 cursor-pointer hover:border-zinc-600 transition-colors"
                  onClick={() => setSelectedRunbook(r)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-zinc-200 text-sm">{r.title}</h3>
                      <Badge className={statusColors[r.status] || "bg-zinc-700"}>{r.status}</Badge>
                    </div>
                    <p className="text-xs text-zinc-400 line-clamp-2 mb-2">{r.scenario}</p>
                    <div className="flex items-center gap-4 text-xs text-zinc-500">
                      {r.estimatedDowntimeHours && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {r.estimatedDowntimeHours}h downtime
                        </span>
                      )}
                      {r.estimatedRecoveryCostUsd && <span>{formatUsd(r.estimatedRecoveryCostUsd)} est. cost</span>}
                      <span>{(r.steps as unknown[])?.length || 0} steps</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent>
                <EmptyState
                  icon={BookOpen}
                  title="No recovery runbooks yet"
                  description="AI-generated step-by-step recovery plans based on specific ransomware variants. Import ransomware group intelligence first, then generate targeted runbooks."
                  action={{
                    label: "Generate Your First Runbook",
                    icon: Zap,
                    onClick: () => setRunbookOpen(true),
                  }}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── TABLETOP EXERCISES TAB ───────────────────────────────────── */}
        <TabsContent value="exercises" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-zinc-200">Tabletop Exercises</h2>
              <p className="text-sm text-zinc-400">
                Simulate ransomware attacks for training. Use templates or create custom scenarios.
              </p>
            </div>
            <Button className="gap-1.5" onClick={() => setExerciseOpen(true)}>
              <Plus className="h-4 w-4" />
              New Exercise
            </Button>
          </div>

          {/* Templates */}
          {exerciseTemplates && exerciseTemplates.length > 0 && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">Exercise Templates</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {exerciseTemplates.map((t, i) => (
                    <div key={i} className="border border-zinc-800 rounded p-3 hover:border-zinc-600 transition-colors">
                      <div className="flex items-center justify-between mb-1">
                        <h4 className="text-sm font-medium text-zinc-300">{t.title}</h4>
                        <Badge variant="outline" className="text-xs">
                          {t.difficulty}
                        </Badge>
                      </div>
                      <p className="text-xs text-zinc-500 mb-2">{t.description}</p>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-zinc-500">{t.durationMinutes} min</span>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 text-xs border-zinc-700"
                          onClick={() =>
                            createExercise.mutate({
                              templateIndex: i,
                              scenarioType: t.scenarioType,
                              difficulty: t.difficulty,
                            })
                          }
                        >
                          Use Template
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Exercise List */}
          {exercises && exercises.length > 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-400">Title</TableHead>
                      <TableHead className="text-zinc-400">Type</TableHead>
                      <TableHead className="text-zinc-400">Difficulty</TableHead>
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">Score</TableHead>
                      <TableHead className="text-zinc-400">Created</TableHead>
                      <TableHead className="text-zinc-400">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {exercises.map((e) => (
                      <TableRow
                        key={e.id}
                        className="border-zinc-800 hover:bg-zinc-800/50 cursor-pointer"
                        onClick={() => setSelectedExercise(e)}
                      >
                        <TableCell className="text-zinc-300 font-medium">{e.title}</TableCell>
                        <TableCell className="text-zinc-400 text-sm">{e.scenarioType}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {e.difficulty}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={statusColors[e.status] || "bg-zinc-700"}>{e.status}</Badge>
                        </TableCell>
                        <TableCell>{e.score != null ? `${e.score}/100` : "—"}</TableCell>
                        <TableCell className="text-zinc-500 text-xs">{formatDate(e.createdAt)}</TableCell>
                        <TableCell>
                          <div className="flex gap-1" onClick={(ev) => ev.stopPropagation()}>
                            {e.status === "draft" && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-6 text-xs border-zinc-700 gap-1"
                                onClick={() => updateExercise.mutate({ id: e.id, status: "in_progress" })}
                              >
                                <Play className="h-3 w-3" /> Start
                              </Button>
                            )}
                            {e.status === "in_progress" && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-6 text-xs border-zinc-700 gap-1"
                                onClick={() => updateExercise.mutate({ id: e.id, status: "completed", score: 75 })}
                              >
                                <CheckCircle2 className="h-3 w-3" /> Complete
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 w-6 p-0 text-zinc-400 hover:text-red-400"
                              onClick={() => deleteExercise.mutate(e.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          ) : (
            !exerciseTemplates?.length && (
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardContent>
                  <EmptyState
                    icon={Users}
                    title="No exercises created yet"
                    description="Tabletop exercises simulate ransomware attacks for training. Use predefined templates or create custom scenarios to test your incident response procedures."
                    action={{
                      label: "Create Your First Exercise",
                      icon: Plus,
                      onClick: () => setExerciseOpen(true),
                    }}
                  />
                </CardContent>
              </Card>
            )
          )}
        </TabsContent>

        {/* ── BACKUPS TAB ──────────────────────────────────────────────── */}
        <TabsContent value="backups" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-zinc-200">Backup Integrity Verification</h2>
              <p className="text-sm text-zinc-400">Verify your backups are actually restorable before you need them</p>
            </div>
            <Button className="gap-1.5" onClick={() => setBackupOpen(true)}>
              <Plus className="h-4 w-4" />
              Register Backup
            </Button>
          </div>

          {backups && backups.length > 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-400">Name</TableHead>
                      <TableHead className="text-zinc-400">Type</TableHead>
                      <TableHead className="text-zinc-400">Location</TableHead>
                      <TableHead className="text-zinc-400">Encryption</TableHead>
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">Integrity</TableHead>
                      <TableHead className="text-zinc-400">Last Verified</TableHead>
                      <TableHead className="text-zinc-400">Issues</TableHead>
                      <TableHead className="text-zinc-400">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {backups.map((b) => (
                      <TableRow key={b.id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell className="text-zinc-300 font-medium">{b.backupName}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {b.backupType}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-zinc-400 text-xs max-w-[150px] truncate">
                          {b.backupLocation}
                        </TableCell>
                        <TableCell>
                          {b.encryptionStatus === "encrypted" ? (
                            <span className="flex items-center gap-1 text-green-400 text-xs">
                              <Lock className="h-3 w-3" /> Encrypted
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-red-400 text-xs">
                              <XCircle className="h-3 w-3" /> {b.encryptionStatus || "Unknown"}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge className={statusColors[b.status] || "bg-zinc-700"}>{b.status}</Badge>
                        </TableCell>
                        <TableCell>
                          {b.integrityCheckResult ? (
                            <Badge
                              className={
                                b.integrityCheckResult === "passed"
                                  ? "bg-green-500/20 text-green-400"
                                  : "bg-red-500/20 text-red-400"
                              }
                            >
                              {b.integrityCheckResult}
                            </Badge>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell className="text-zinc-500 text-xs">{formatDate(b.lastVerifiedAt)}</TableCell>
                        <TableCell>
                          {b.issues && (b.issues as unknown[]).length > 0 ? (
                            <span className="text-red-400 text-xs">{(b.issues as unknown[]).length} issues</span>
                          ) : b.integrityCheckResult ? (
                            <span className="text-green-400 text-xs">None</span>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-6 text-xs border-zinc-700 gap-1"
                              onClick={() => verifyBackup.mutate(b.id)}
                              disabled={verifyBackup.isPending}
                            >
                              <RefreshCw className="h-3 w-3" /> Verify
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 w-6 p-0 text-zinc-400 hover:text-red-400"
                              onClick={() => deleteBackup.mutate(b.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          ) : (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent>
                <EmptyState
                  icon={HardDrive}
                  title="No backups registered for verification"
                  description="Register your backup targets (S3, Azure Blob, on-prem NAS) to continuously verify they are restorable and not compromised by ransomware."
                  action={{
                    label: "Register Your First Backup",
                    icon: Plus,
                    onClick: () => setBackupOpen(true),
                  }}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* ── DIALOGS ──────────────────────────────────────────────────── */}

      {/* Kill Switch Confirmation Dialog */}
      <Dialog open={killSwitchOpen} onOpenChange={setKillSwitchOpen}>
        <DialogContent className="bg-zinc-900 border-red-500/50">
          <DialogHeader>
            <DialogTitle className="text-red-400 flex items-center gap-2">
              <AlertOctagon className="h-5 w-5" />
              Confirm Kill Switch Activation
            </DialogTitle>
            <DialogDescription>
              This will create isolate_host response actions for ALL active sensors in your organization. All endpoints
              will be isolated from the network. This is an emergency action.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-zinc-400 text-xs">Reason (required)</Label>
              <Textarea
                value={killSwitchReason}
                onChange={(e) => setKillSwitchReason(e.target.value)}
                placeholder="Active ransomware encryption detected on multiple hosts..."
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">Incident ID (optional)</Label>
              <Input
                value={killSwitchIncident}
                onChange={(e) => setKillSwitchIncident(e.target.value)}
                placeholder="INC-2026-001"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-zinc-700" onClick={() => setKillSwitchOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-red-600 hover:bg-red-700 text-white gap-1"
              onClick={() =>
                activateKillSwitch.mutate({ reason: killSwitchReason, incidentId: killSwitchIncident || undefined })
              }
              disabled={!killSwitchReason.trim() || activateKillSwitch.isPending}
            >
              <PowerOff className="h-4 w-4" />
              {activateKillSwitch.isPending ? "Isolating..." : "ISOLATE ALL ENDPOINTS"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Deploy Canary Dialog */}
      <Dialog open={canaryDeployOpen} onOpenChange={setCanaryDeployOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Deploy Canary File</DialogTitle>
            <DialogDescription>Create a fake "important" file that alerts if accessed or encrypted.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-zinc-400 text-xs">File Name</Label>
              <Input
                value={canaryFileName}
                onChange={(e) => setCanaryFileName(e.target.value)}
                placeholder="Q4_Financial_Report_2025.xlsx"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">File Path</Label>
              <Input
                value={canaryFilePath}
                onChange={(e) => setCanaryFilePath(e.target.value)}
                placeholder="C:\\Users\\Shared\\Documents"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-zinc-400 text-xs">File Type</Label>
                <Select value={canaryFileType} onValueChange={setCanaryFileType}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="xlsx">Excel (.xlsx)</SelectItem>
                    <SelectItem value="docx">Word (.docx)</SelectItem>
                    <SelectItem value="pdf">PDF (.pdf)</SelectItem>
                    <SelectItem value="pptx">PowerPoint (.pptx)</SelectItem>
                    <SelectItem value="sql">SQL (.sql)</SelectItem>
                    <SelectItem value="txt">Text (.txt)</SelectItem>
                    <SelectItem value="key">Key (.key)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-zinc-400 text-xs">Target Host</Label>
                <Input
                  value={canaryHost}
                  onChange={(e) => setCanaryHost(e.target.value)}
                  placeholder="fileserver-01"
                  className="bg-zinc-800 border-zinc-700 mt-1"
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-zinc-700" onClick={() => setCanaryDeployOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                deployCanary.mutate({
                  fileName: canaryFileName,
                  filePath: canaryFilePath,
                  fileType: canaryFileType,
                  deployedToHost: canaryHost || undefined,
                })
              }
              disabled={!canaryFileName.trim() || !canaryFilePath.trim() || deployCanary.isPending}
            >
              Deploy
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Deploy Templates Dialog */}
      <Dialog open={canaryTemplateOpen} onOpenChange={setCanaryTemplateOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Deploy Canary Template Pack</DialogTitle>
            <DialogDescription>
              Deploy {canaryTemplates?.length || 10} realistic-looking canary files to a target directory.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-zinc-400 text-xs">Deploy Path</Label>
              <Input
                value={canaryTemplatePath}
                onChange={(e) => setCanaryTemplatePath(e.target.value)}
                placeholder="C:\\Users\\Shared\\Important_Documents"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">Target Host</Label>
              <Input
                value={canaryTemplateHost}
                onChange={(e) => setCanaryTemplateHost(e.target.value)}
                placeholder="fileserver-01"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-zinc-700" onClick={() => setCanaryTemplateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                deployCanaryTemplates.mutate({
                  deployPath: canaryTemplatePath,
                  hostName: canaryTemplateHost || undefined,
                })
              }
              disabled={!canaryTemplatePath.trim() || deployCanaryTemplates.isPending}
            >
              Deploy All Templates
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Generate Runbook Dialog */}
      <Dialog open={runbookOpen} onOpenChange={setRunbookOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Generate Recovery Runbook</DialogTitle>
            <DialogDescription>AI generates a step-by-step recovery plan based on your scenario.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-zinc-400 text-xs">Scenario Description</Label>
              <Textarea
                value={runbookScenario}
                onChange={(e) => setRunbookScenario(e.target.value)}
                placeholder="Ransomware encrypted file servers and domain controllers at 3 AM..."
                className="bg-zinc-800 border-zinc-700 mt-1"
                rows={3}
              />
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">Affected Systems (comma-separated)</Label>
              <Input
                value={runbookSystems}
                onChange={(e) => setRunbookSystems(e.target.value)}
                placeholder="DC-01, FS-01, Exchange, SQL-Prod"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">Affected Data Types (comma-separated)</Label>
              <Input
                value={runbookDataTypes}
                onChange={(e) => setRunbookDataTypes(e.target.value)}
                placeholder="PII, PHI, PCI, financial"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">Ransomware Variant (optional)</Label>
              <Input
                value={runbookVariant}
                onChange={(e) => setRunbookVariant(e.target.value)}
                placeholder="LockBit 3.0"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-zinc-700" onClick={() => setRunbookOpen(false)}>
              Cancel
            </Button>
            <Button
              className="gap-1"
              onClick={() =>
                generateRunbook.mutate({
                  scenario: runbookScenario,
                  affectedSystems: runbookSystems
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                  affectedDataTypes: runbookDataTypes
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                  ransomwareVariant: runbookVariant || undefined,
                })
              }
              disabled={!runbookScenario.trim() || generateRunbook.isPending}
            >
              <Zap className="h-4 w-4" />
              {generateRunbook.isPending ? "Generating..." : "Generate Runbook"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Runbook Detail Dialog */}
      <Dialog open={!!selectedRunbook} onOpenChange={() => setSelectedRunbook(null)}>
        <DialogContent className="bg-zinc-900 border-zinc-800 max-w-3xl max-h-[80vh] overflow-y-auto">
          {selectedRunbook && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <BookOpen className="h-5 w-5 text-blue-400" />
                  {selectedRunbook.title}
                </DialogTitle>
                <DialogDescription>{selectedRunbook.scenario}</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="border border-zinc-800 rounded p-2 text-center">
                    <div className="text-xs text-zinc-400">Est. Downtime</div>
                    <div className="text-lg font-bold text-zinc-200">{selectedRunbook.estimatedDowntimeHours}h</div>
                  </div>
                  <div className="border border-zinc-800 rounded p-2 text-center">
                    <div className="text-xs text-zinc-400">Est. Cost</div>
                    <div className="text-lg font-bold text-zinc-200">
                      {formatUsd(selectedRunbook.estimatedRecoveryCostUsd)}
                    </div>
                  </div>
                  <div className="border border-zinc-800 rounded p-2 text-center">
                    <div className="text-xs text-zinc-400">Steps</div>
                    <div className="text-lg font-bold text-zinc-200">
                      {(selectedRunbook.steps as unknown[])?.length || 0}
                    </div>
                  </div>
                </div>

                {selectedRunbook.priorityActions && (selectedRunbook.priorityActions as string[]).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-red-400 mb-2">Priority Actions</h4>
                    <div className="space-y-1">
                      {(selectedRunbook.priorityActions as string[]).map((a, i) => (
                        <p key={i} className="text-xs text-zinc-400 flex items-start gap-1">
                          <AlertTriangle className="h-3 w-3 text-red-400 mt-0.5 shrink-0" />
                          {a}
                        </p>
                      ))}
                    </div>
                  </div>
                )}

                {selectedRunbook.steps && (
                  <div>
                    <h4 className="text-sm font-medium text-zinc-300 mb-2">Recovery Steps</h4>
                    <div className="space-y-2">
                      {(
                        selectedRunbook.steps as {
                          order: number;
                          title: string;
                          description: string;
                          responsible: string;
                          estimatedMinutes: number;
                        }[]
                      ).map((s) => (
                        <div key={s.order} className="border border-zinc-800 rounded p-3">
                          <div className="flex items-center justify-between mb-1">
                            <h5 className="text-sm font-medium text-zinc-200">
                              {s.order}. {s.title}
                            </h5>
                            <div className="flex items-center gap-2 text-xs text-zinc-500">
                              <span>{s.responsible}</span>
                              <span>{s.estimatedMinutes} min</span>
                            </div>
                          </div>
                          <p className="text-xs text-zinc-400">{s.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedRunbook.communicationPlan && (selectedRunbook.communicationPlan as unknown[]).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-zinc-300 mb-2">Communication Plan</h4>
                    <Table>
                      <TableHeader>
                        <TableRow className="border-zinc-800">
                          <TableHead className="text-zinc-400 text-xs">Stakeholder</TableHead>
                          <TableHead className="text-zinc-400 text-xs">Timing</TableHead>
                          <TableHead className="text-zinc-400 text-xs">Channel</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(
                          selectedRunbook.communicationPlan as {
                            stakeholder: string;
                            timing: string;
                            channel: string;
                          }[]
                        ).map((c, i) => (
                          <TableRow key={i} className="border-zinc-800">
                            <TableCell className="text-xs text-zinc-300">{c.stakeholder}</TableCell>
                            <TableCell className="text-xs text-zinc-400">{c.timing}</TableCell>
                            <TableCell className="text-xs text-zinc-400">{c.channel}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Exercise Detail Dialog */}
      <Dialog open={!!selectedExercise} onOpenChange={() => setSelectedExercise(null)}>
        <DialogContent className="bg-zinc-900 border-zinc-800 max-w-3xl max-h-[80vh] overflow-y-auto">
          {selectedExercise && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5 text-purple-400" />
                  {selectedExercise.title}
                </DialogTitle>
                <DialogDescription>
                  {selectedExercise.scenarioType} scenario — {selectedExercise.difficulty} difficulty —{" "}
                  {selectedExercise.durationMinutes} minutes
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                {selectedExercise.scenario && (
                  <div className="space-y-3">
                    <div className="border border-zinc-800 rounded p-3">
                      <h5 className="text-xs font-medium text-zinc-400 mb-1">Background</h5>
                      <p className="text-xs text-zinc-300">{selectedExercise.scenario.background}</p>
                    </div>
                    <div className="border border-zinc-800 rounded p-3">
                      <h5 className="text-xs font-medium text-red-400 mb-1">Initial Compromise</h5>
                      <p className="text-xs text-zinc-300">{selectedExercise.scenario.initialCompromise}</p>
                    </div>
                    <div className="border border-zinc-800 rounded p-3">
                      <h5 className="text-xs font-medium text-orange-400 mb-1">Escalation</h5>
                      <p className="text-xs text-zinc-300">{selectedExercise.scenario.escalation}</p>
                    </div>
                    <div className="border border-zinc-800 rounded p-3">
                      <h5 className="text-xs font-medium text-red-400 mb-1">Impact</h5>
                      <p className="text-xs text-zinc-300">{selectedExercise.scenario.impact}</p>
                    </div>
                    {selectedExercise.scenario.objectives && (
                      <div>
                        <h5 className="text-xs font-medium text-zinc-400 mb-1">Objectives</h5>
                        <ul className="space-y-1">
                          {selectedExercise.scenario.objectives.map((o, i) => (
                            <li key={i} className="text-xs text-zinc-300 flex items-start gap-1">
                              <CheckCircle2 className="h-3 w-3 text-green-400 mt-0.5 shrink-0" />
                              {o}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {selectedExercise.injects && (selectedExercise.injects as unknown[]).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-zinc-300 mb-2">Scenario Injects</h4>
                    <div className="space-y-2">
                      {(
                        selectedExercise.injects as {
                          order: number;
                          timeMinutes: number;
                          description: string;
                          expectedResponse: string;
                          hint: string;
                        }[]
                      ).map((inj) => (
                        <div key={inj.order} className="border border-zinc-800 rounded p-3">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant="outline" className="text-xs">
                              T+{inj.timeMinutes}m
                            </Badge>
                            <span className="text-xs font-medium text-zinc-300">Inject #{inj.order}</span>
                          </div>
                          <p className="text-xs text-zinc-300 mb-2">{inj.description}</p>
                          <div className="bg-zinc-800/50 rounded p-2">
                            <p className="text-xs text-green-400">Expected: {inj.expectedResponse}</p>
                            <p className="text-xs text-zinc-500 mt-1">Hint: {inj.hint}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Group Detail Dialog */}
      <Dialog open={!!selectedGroup} onOpenChange={() => setSelectedGroup(null)}>
        <DialogContent className="bg-zinc-900 border-zinc-800 max-w-3xl max-h-[80vh] overflow-y-auto">
          {selectedGroup && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Skull className="h-5 w-5 text-red-400" />
                  {selectedGroup.name}
                  <Badge className={severityColors[selectedGroup.threatLevel] || "bg-zinc-700"}>
                    {selectedGroup.threatLevel}
                  </Badge>
                  {selectedGroup.isActive ? (
                    <Badge className="bg-red-500/20 text-red-400">Active</Badge>
                  ) : (
                    <Badge className="bg-zinc-500/20 text-zinc-400">Inactive</Badge>
                  )}
                </DialogTitle>
                <DialogDescription>{selectedGroup.description}</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="border border-zinc-800 rounded p-2 text-center">
                    <div className="text-xs text-zinc-400">Avg Ransom</div>
                    <div className="text-sm font-bold text-zinc-200">{formatUsd(selectedGroup.avgRansomDemandUsd)}</div>
                  </div>
                  <div className="border border-zinc-800 rounded p-2 text-center">
                    <div className="text-xs text-zinc-400">First Seen</div>
                    <div className="text-sm font-bold text-zinc-200">{selectedGroup.firstSeen || "—"}</div>
                  </div>
                  <div className="border border-zinc-800 rounded p-2 text-center">
                    <div className="text-xs text-zinc-400">Decryptor</div>
                    <div
                      className={`text-sm font-bold ${selectedGroup.decryptorAvailable ? "text-green-400" : "text-red-400"}`}
                    >
                      {selectedGroup.decryptorAvailable ? "Available" : "None"}
                    </div>
                  </div>
                </div>

                {selectedGroup.decryptorSource && (
                  <div className="bg-green-500/10 border border-green-500/30 rounded p-3">
                    <p className="text-xs text-green-400">Decryptor source: {selectedGroup.decryptorSource}</p>
                  </div>
                )}

                {selectedGroup.aliases && (selectedGroup.aliases as string[]).length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium text-zinc-400 mb-1">Aliases</h5>
                    <div className="flex flex-wrap gap-1">
                      {(selectedGroup.aliases as string[]).map((a, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {a}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selectedGroup.ttps && (selectedGroup.ttps as unknown[]).length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium text-zinc-400 mb-1">MITRE ATT&CK TTPs</h5>
                    <div className="grid grid-cols-2 gap-1">
                      {(selectedGroup.ttps as { id: string; name: string; tactic: string }[]).map((t, i) => (
                        <div
                          key={i}
                          className="text-xs border border-zinc-800 rounded px-2 py-1 flex items-center gap-1"
                        >
                          <span className="text-red-400 font-mono">{t.id}</span>
                          <span className="text-zinc-400">{t.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedGroup.targetIndustries && (selectedGroup.targetIndustries as string[]).length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium text-zinc-400 mb-1">Target Industries</h5>
                    <div className="flex flex-wrap gap-1">
                      {(selectedGroup.targetIndustries as string[]).map((ind, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {ind}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selectedGroup.ransomwareVariants && (selectedGroup.ransomwareVariants as unknown[]).length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium text-zinc-400 mb-1">Known Variants</h5>
                    <div className="flex flex-wrap gap-1">
                      {(selectedGroup.ransomwareVariants as { name: string; type: string }[]).map((v, i) => (
                        <Badge key={i} className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          {v.name} ({v.type})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selectedGroup.iocIndicators && (selectedGroup.iocIndicators as unknown[]).length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium text-zinc-400 mb-1">IOC Indicators</h5>
                    <div className="space-y-1">
                      {(selectedGroup.iocIndicators as { type: string; value: string }[]).map((ioc, i) => (
                        <div key={i} className="text-xs flex items-center gap-2">
                          <Badge variant="outline" className="text-xs min-w-[80px] justify-center">
                            {ioc.type}
                          </Badge>
                          <code className="text-zinc-300 bg-zinc-800 px-2 py-0.5 rounded">{ioc.value}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedGroup.referenceUrls && (selectedGroup.referenceUrls as string[]).length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium text-zinc-400 mb-1">References</h5>
                    <div className="space-y-1">
                      {(selectedGroup.referenceUrls as string[]).map((url, i) => (
                        <a
                          key={i}
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-blue-400 hover:underline block truncate"
                        >
                          {url}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Create Exercise Dialog */}
      <Dialog open={exerciseOpen} onOpenChange={setExerciseOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Create Tabletop Exercise</DialogTitle>
            <DialogDescription>Create a custom ransomware scenario or use a template.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-zinc-400 text-xs">Title</Label>
              <Input
                value={exerciseTitle}
                onChange={(e) => setExerciseTitle(e.target.value)}
                placeholder="Healthcare Ransomware Simulation"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-zinc-400 text-xs">Scenario Type</Label>
                <Select value={exerciseType} onValueChange={setExerciseType}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ransomware">Ransomware</SelectItem>
                    <SelectItem value="data_breach">Data Breach</SelectItem>
                    <SelectItem value="insider_threat">Insider Threat</SelectItem>
                    <SelectItem value="supply_chain">Supply Chain</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-zinc-400 text-xs">Difficulty</Label>
                <Select value={exerciseDifficulty} onValueChange={setExerciseDifficulty}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="beginner">Beginner</SelectItem>
                    <SelectItem value="intermediate">Intermediate</SelectItem>
                    <SelectItem value="advanced">Advanced</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-zinc-700" onClick={() => setExerciseOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                createExercise.mutate({
                  title: exerciseTitle,
                  scenarioType: exerciseType,
                  difficulty: exerciseDifficulty,
                })
              }
              disabled={!exerciseTitle.trim() || createExercise.isPending}
            >
              Create Exercise
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Register Backup Dialog */}
      <Dialog open={backupOpen} onOpenChange={setBackupOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Register Backup for Verification</DialogTitle>
            <DialogDescription>Register a backup source to verify its integrity and restorability.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-zinc-400 text-xs">Backup Name</Label>
              <Input
                value={backupName}
                onChange={(e) => setBackupName(e.target.value)}
                placeholder="Production DB — Daily Full"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-zinc-400 text-xs">Backup Type</Label>
                <Select value={backupType} onValueChange={setBackupType}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="full">Full</SelectItem>
                    <SelectItem value="incremental">Incremental</SelectItem>
                    <SelectItem value="differential">Differential</SelectItem>
                    <SelectItem value="snapshot">Snapshot</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-zinc-400 text-xs">Encryption</Label>
                <Select value={backupEncryption} onValueChange={setBackupEncryption}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="encrypted">Encrypted</SelectItem>
                    <SelectItem value="unencrypted">Unencrypted</SelectItem>
                    <SelectItem value="unknown">Unknown</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label className="text-zinc-400 text-xs">Backup Location</Label>
              <Input
                value={backupLocation}
                onChange={(e) => setBackupLocation(e.target.value)}
                placeholder="s3://backups-prod/daily-full/"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-zinc-700" onClick={() => setBackupOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                registerBackup.mutate({ backupName, backupType, backupLocation, encryptionStatus: backupEncryption })
              }
              disabled={!backupName.trim() || !backupLocation.trim() || registerBackup.isPending}
            >
              Register Backup
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
