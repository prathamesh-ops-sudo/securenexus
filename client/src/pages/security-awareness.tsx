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
  Mail,
  Plus,
  Search,
  Shield,
  AlertTriangle,
  RefreshCw,
  Clock,
  CheckCircle2,
  XCircle,
  Activity,
  Users,
  Loader2,
  Target,
  Play,
  Square,
  BarChart3,
  BookOpen,
  GraduationCap,
  TrendingUp,
  TrendingDown,
  Minus,
  Phone,
  MessageSquare,
  FileText,
  Video,
  Brain,
  Zap,
  UserX,
  Eye,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { SunIcon, ThunderIcon } from "@/components/ui/animated-weather-icons";
import { apiRequest } from "@/lib/queryClient";
import { FormPageSkeleton } from "@/components/page-skeleton";

// ── Types ─────────────────────────────────────────────────────────

interface PhishingCampaign {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  status: string;
  templateCategory: string | null;
  senderName: string | null;
  senderEmail: string | null;
  subject: string | null;
  totalRecipients: number;
  emailsSent: number;
  emailsOpened: number;
  linksClicked: number;
  credentialsSubmitted: number;
  reported: number;
  scheduledAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

interface PhishingTemplate {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  industry: string | null;
  subject: string;
  senderName: string;
  senderEmail: string;
  isBuiltIn: boolean;
  usageCount: number;
  successRate: number | null;
  createdAt: string;
}

interface EmployeeRiskScore {
  id: string;
  email: string;
  name: string | null;
  department: string | null;
  riskScore: number;
  phishingClickRate: number;
  reportRate: number;
  trainingCompletionRate: number;
  campaignsReceived: number;
  campaignsClicked: number;
  campaignsReported: number;
  trainingsCompleted: number;
  trainingsAssigned: number;
  lastPhishingTestAt: string | null;
  lastTrainingCompletedAt: string | null;
  riskTrend: string;
}

interface TrainingModule {
  id: string;
  title: string;
  description: string | null;
  moduleType: string;
  category: string;
  difficulty: string;
  durationMinutes: number;
  passingScore: number | null;
  isBuiltIn: boolean;
  isActive: boolean;
  completionCount: number;
  averageScore: number | null;
  createdAt: string;
}

interface TrainingAssignment {
  id: string;
  moduleId: string;
  employeeEmail: string;
  employeeName: string | null;
  assignedReason: string | null;
  assignedAt: string;
  dueAt: string | null;
  completedAt: string | null;
  score: number | null;
  passed: boolean | null;
  attempts: number;
}

interface Dashboard {
  totalCampaigns: number;
  activeCampaigns: number;
  totalTemplates: number;
  totalEmployees: number;
  highRiskCount: number;
  totalModules: number;
  pendingAssignments: number;
  avgClickRate: number;
  topRiskyEmployees: EmployeeRiskScore[];
  recentCampaigns: PhishingCampaign[];
  // 68.2 — Campaign results summary
  campaignResults?: Array<{ id: string; name: string; clickRate: number; reportRate: number; submissionRate: number }>;
  // 68.5 — Email delivery stats
  deliveryStats?: { totalSent: number; totalOpened: number; totalClicked: number; totalReported: number };
  // 68.6 — Click/submission tracking accuracy
  trackingAccuracy?: number;
}

// ── Helpers ───────────────────────────────────────────────────────

function campaignStatusColor(status: string) {
  switch (status) {
    case "draft":
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
    case "scheduled":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    case "running":
      return "bg-green-500/10 text-green-400 border-green-500/20";
    case "completed":
      return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    case "paused":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function riskScoreColor(score: number) {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-yellow-400";
  if (score >= 25) return "text-blue-400";
  return "text-green-400";
}

function riskScoreBg(score: number) {
  if (score >= 75) return "bg-red-500/10 border-red-500/20";
  if (score >= 50) return "bg-yellow-500/10 border-yellow-500/20";
  if (score >= 25) return "bg-blue-500/10 border-blue-500/20";
  return "bg-green-500/10 border-green-500/20";
}

function trendIcon(trend: string) {
  switch (trend) {
    case "improving":
      return <TrendingDown className="h-3 w-3 text-green-400" />;
    case "worsening":
      return <TrendingUp className="h-3 w-3 text-red-400" />;
    default:
      return <Minus className="h-3 w-3 text-zinc-400" />;
  }
}

function categoryIcon(category: string) {
  switch (category) {
    case "credential_harvest":
      return <Target className="h-4 w-4 text-red-400" />;
    case "malware_download":
      return <AlertTriangle className="h-4 w-4 text-orange-400" />;
    case "spear_phishing":
      return <Mail className="h-4 w-4 text-blue-400" />;
    case "whaling":
      return <UserX className="h-4 w-4 text-purple-400" />;
    case "vishing":
      return <Phone className="h-4 w-4 text-yellow-400" />;
    case "smishing":
      return <MessageSquare className="h-4 w-4 text-green-400" />;
    default:
      return <Mail className="h-4 w-4 text-zinc-400" />;
  }
}

function moduleTypeIcon(type: string) {
  switch (type) {
    case "video":
      return <Video className="h-4 w-4 text-blue-400" />;
    case "quiz":
      return <Brain className="h-4 w-4 text-purple-400" />;
    case "interactive":
      return <Zap className="h-4 w-4 text-yellow-400" />;
    case "document":
      return <FileText className="h-4 w-4 text-zinc-400" />;
    case "simulation":
      return <Target className="h-4 w-4 text-red-400" />;
    case "micro_learning":
      return <BookOpen className="h-4 w-4 text-green-400" />;
    default:
      return <FileText className="h-4 w-4 text-zinc-400" />;
  }
}

function difficultyColor(d: string) {
  switch (d) {
    case "easy":
    case "beginner":
      return "bg-green-500/10 text-green-400 border-green-500/20";
    case "medium":
    case "intermediate":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    case "hard":
    case "advanced":
      return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "expert":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function formatLabel(s: string) {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatDateTime(ts: string | null) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString();
}

function pct(n: number, d: number) {
  if (d === 0) return "0%";
  return `${Math.round((n / d) * 100)}%`;
}

const TEMPLATE_CATEGORIES = [
  "credential_harvest",
  "malware_download",
  "data_entry",
  "reply_to",
  "smishing",
  "vishing",
  "spear_phishing",
  "whaling",
];

const MODULE_TYPES = ["video", "quiz", "interactive", "document", "simulation", "micro_learning"];

const TRAINING_CATEGORIES = [
  "phishing_awareness",
  "password_security",
  "social_engineering",
  "data_handling",
  "insider_threat",
  "physical_security",
];

// ── Main Component ────────────────────────────────────────────────

export default function SecurityAwarenessPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const { toast } = useToast();
  const qc = useQueryClient();

  const [campaignSearch, setCampaignSearch] = useState("");
  const [riskSearch, setRiskSearch] = useState("");
  const [showAddCampaign, setShowAddCampaign] = useState(false);
  const [showAddTemplate, setShowAddTemplate] = useState(false);
  const [showAddModule, setShowAddModule] = useState(false);

  // Dashboard
  const { data: dashboard } = useQuery<Dashboard>({
    queryKey: ["/api/security-awareness/dashboard"],
  });

  // Campaigns
  const { data: campaignsData, isLoading: campaignsLoading } = useQuery<{ items: PhishingCampaign[]; total: number }>({
    queryKey: ["/api/security-awareness/campaigns", campaignSearch],
    queryFn: () =>
      apiRequest("GET", `/api/security-awareness/campaigns?limit=50&search=${encodeURIComponent(campaignSearch)}`).then(
        (r) => r.json(),
      ),
  });

  // Templates
  const { data: templatesData } = useQuery<{ items: PhishingTemplate[]; total: number }>({
    queryKey: ["/api/security-awareness/templates"],
    queryFn: () => apiRequest("GET", "/api/security-awareness/templates?limit=50").then((r) => r.json()),
  });

  // Risk Scores
  const { data: riskData } = useQuery<{ items: EmployeeRiskScore[]; total: number }>({
    queryKey: ["/api/security-awareness/risk-scores", riskSearch],
    queryFn: () =>
      apiRequest("GET", `/api/security-awareness/risk-scores?limit=50&search=${encodeURIComponent(riskSearch)}`).then(
        (r) => r.json(),
      ),
  });

  // Training Modules
  const { data: modulesData } = useQuery<{ items: TrainingModule[]; total: number }>({
    queryKey: ["/api/security-awareness/training/modules"],
    queryFn: () => apiRequest("GET", "/api/security-awareness/training/modules?limit=50").then((r) => r.json()),
  });

  // Training Assignments
  const { data: assignmentsData } = useQuery<{ items: TrainingAssignment[]; total: number }>({
    queryKey: ["/api/security-awareness/training/assignments"],
    queryFn: () => apiRequest("GET", "/api/security-awareness/training/assignments?limit=50").then((r) => r.json()),
  });

  // Mutations
  const createCampaignMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/security-awareness/campaigns", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/campaigns"] });
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/dashboard"] });
      setShowAddCampaign(false);
      toast({ title: "Campaign created" });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create campaign", description: err.message, variant: "destructive" }),
  });

  const launchCampaignMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/security-awareness/campaigns/${id}/launch`).then((r) => r.json()),
    onSuccess: (data: { sent: number }) => {
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/campaigns"] });
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/dashboard"] });
      toast({ title: `Campaign launched — ${data.sent} emails sent` });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to launch campaign", description: err.message, variant: "destructive" }),
  });

  const completeCampaignMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/security-awareness/campaigns/${id}/complete`).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/campaigns"] });
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/dashboard"] });
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/risk-scores"] });
      toast({ title: "Campaign completed — risk scores recalculated" });
    },
  });

  const createTemplateMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/security-awareness/templates", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/templates"] });
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/dashboard"] });
      setShowAddTemplate(false);
      toast({ title: "Template created" });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create template", description: err.message, variant: "destructive" }),
  });

  const createModuleMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/security-awareness/training/modules", data).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/training/modules"] });
      qc.invalidateQueries({ queryKey: ["/api/security-awareness/dashboard"] });
      setShowAddModule(false);
      toast({ title: "Training module created" });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create module", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Phishing Simulation & Security Awareness</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Human risk mitigation — phishing campaigns, click tracking, adaptive training, and vishing simulation
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="risk-scores">Risk Scores</TabsTrigger>
          <TabsTrigger value="training">Training</TabsTrigger>
          <TabsTrigger value="vishing">Vishing</TabsTrigger>
        </TabsList>

        {/* ── Overview ─────────────────────────────────────────── */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Campaigns</p>
                    <p className="text-2xl font-bold">{dashboard?.totalCampaigns ?? 0}</p>
                    <p className="text-xs text-muted-foreground">{dashboard?.activeCampaigns ?? 0} active</p>
                  </div>
                  <Mail className="h-8 w-8 text-blue-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Avg Click Rate</p>
                    <p className="text-2xl font-bold">{dashboard?.avgClickRate ?? 0}%</p>
                    <p className="text-xs text-muted-foreground">across all employees</p>
                  </div>
                  <Target className="h-8 w-8 text-orange-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">High Risk Employees</p>
                    <p className="text-2xl font-bold">{dashboard?.highRiskCount ?? 0}</p>
                    <p className="text-xs text-muted-foreground">score &ge; 75</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Pending Training</p>
                    <p className="text-2xl font-bold">{dashboard?.pendingAssignments ?? 0}</p>
                    <p className="text-xs text-muted-foreground">assignments incomplete</p>
                  </div>
                  <GraduationCap className="h-8 w-8 text-purple-400 opacity-60" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Top Risky Employees */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Top Risk Employees</CardTitle>
              <CardDescription>
                Employees with the highest human risk scores based on phishing click rates and training completion
              </CardDescription>
            </CardHeader>
            <CardContent>
              {(dashboard?.topRiskyEmployees ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">
                  No employee risk data yet. Launch a phishing campaign to start measuring human risk.
                </p>
              ) : (
                <div className="space-y-2">
                  {dashboard?.topRiskyEmployees.map((emp) => (
                    <div
                      key={emp.id}
                      className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${riskScoreBg(emp.riskScore)} ${riskScoreColor(emp.riskScore)}`}
                        >
                          {Math.round(emp.riskScore)}
                        </div>
                        <div>
                          <p className="text-sm font-medium">{emp.name || emp.email}</p>
                          <p className="text-xs text-muted-foreground">
                            {emp.department || "—"} &middot; Click rate: {Math.round(emp.phishingClickRate)}%
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {trendIcon(emp.riskTrend)}
                        <span className="text-xs text-muted-foreground">{formatLabel(emp.riskTrend)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* 68.2 — Campaign Results Dashboard */}
          {dashboard?.campaignResults && dashboard.campaignResults.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Campaign Results Dashboard</CardTitle>
                <CardDescription>Click, report, and submission rates across recent campaigns</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {dashboard.campaignResults.map(
                    (cr: {
                      id: string;
                      name: string;
                      clickRate: number;
                      reportRate: number;
                      submissionRate: number;
                    }) => (
                      <div key={cr.id} className="p-3 border border-border/50 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium">{cr.name}</span>
                        </div>
                        <div className="grid grid-cols-3 gap-4">
                          <div>
                            <p className="text-xs text-muted-foreground">Click Rate</p>
                            <p
                              className={`text-sm font-medium ${cr.clickRate > 20 ? "text-red-400" : cr.clickRate > 10 ? "text-orange-400" : "text-green-400"}`}
                            >
                              {cr.clickRate}%
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Report Rate</p>
                            <p
                              className={`text-sm font-medium ${cr.reportRate > 50 ? "text-green-400" : "text-yellow-400"}`}
                            >
                              {cr.reportRate}%
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Submission Rate</p>
                            <p
                              className={`text-sm font-medium ${cr.submissionRate > 5 ? "text-red-400" : "text-green-400"}`}
                            >
                              {cr.submissionRate}%
                            </p>
                          </div>
                        </div>
                      </div>
                    ),
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 68.5 — Email Delivery Stats */}
          {dashboard?.deliveryStats && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Email Delivery Infrastructure</CardTitle>
                <CardDescription>Aggregate delivery metrics across all campaigns</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <p className="text-2xl font-bold">{dashboard.deliveryStats.totalSent}</p>
                    <p className="text-xs text-muted-foreground">Total Sent</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-blue-400">{dashboard.deliveryStats.totalOpened}</p>
                    <p className="text-xs text-muted-foreground">Total Opened</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-orange-400">{dashboard.deliveryStats.totalClicked}</p>
                    <p className="text-xs text-muted-foreground">Total Clicked</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-green-400">{dashboard.deliveryStats.totalReported}</p>
                    <p className="text-xs text-muted-foreground">Total Reported</p>
                  </div>
                </div>
                {/* 68.6 — Tracking Accuracy */}
                {dashboard.trackingAccuracy != null && (
                  <div className="mt-4 p-3 border border-border/50 rounded-lg text-center">
                    <p className="text-xs text-muted-foreground">Click/Submission Tracking Accuracy</p>
                    <p
                      className={`text-lg font-semibold ${dashboard.trackingAccuracy > 80 ? "text-green-400" : "text-yellow-400"}`}
                    >
                      {dashboard.trackingAccuracy}%
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Recent Campaigns */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Recent Campaigns</CardTitle>
            </CardHeader>
            <CardContent>
              {(dashboard?.recentCampaigns ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">
                  No campaigns yet. Create one to start testing your organization's security awareness.
                </p>
              ) : (
                <div className="space-y-2">
                  {dashboard?.recentCampaigns.map((campaign) => (
                    <div
                      key={campaign.id}
                      className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                    >
                      <div>
                        <p className="text-sm font-medium">{campaign.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {campaign.totalRecipients} recipients &middot; {campaign.linksClicked} clicked &middot;{" "}
                          {campaign.reported} reported
                        </p>
                      </div>
                      <Badge variant="outline" className={`${campaignStatusColor(campaign.status)} text-xs`}>
                        {campaign.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Campaigns ────────────────────────────────────────── */}
        <TabsContent value="campaigns" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search campaigns..."
                value={campaignSearch}
                onChange={(e) => setCampaignSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Dialog open={showAddCampaign} onOpenChange={setShowAddCampaign}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" /> New Campaign
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Create Phishing Campaign</DialogTitle>
                  <DialogDescription>Set up a simulated phishing campaign to test employee awareness</DialogDescription>
                </DialogHeader>
                <AddCampaignForm
                  onSubmit={(data) => createCampaignMutation.mutate(data)}
                  isPending={createCampaignMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>

          {campaignsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : (campaignsData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No campaigns yet. Create a phishing simulation campaign to measure employee security awareness.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {campaignsData?.items.map((campaign) => (
                <Card key={campaign.id}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Mail className="h-4 w-4 text-blue-400" />
                          <p className="text-sm font-medium">{campaign.name}</p>
                          <Badge variant="outline" className={`${campaignStatusColor(campaign.status)} text-xs`}>
                            {campaign.status}
                          </Badge>
                        </div>
                        {campaign.description && (
                          <p className="text-xs text-muted-foreground mt-1">{campaign.description}</p>
                        )}

                        {/* Stats */}
                        <div className="grid grid-cols-5 gap-4 mt-3">
                          <div>
                            <p className="text-xs text-muted-foreground">Sent</p>
                            <p className="text-sm font-medium">{campaign.emailsSent}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Opened</p>
                            <p className="text-sm font-medium">
                              {campaign.emailsOpened}{" "}
                              <span className="text-xs text-muted-foreground">
                                {pct(campaign.emailsOpened, campaign.emailsSent)}
                              </span>
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Clicked</p>
                            <p className="text-sm font-medium text-orange-400">
                              {campaign.linksClicked}{" "}
                              <span className="text-xs">{pct(campaign.linksClicked, campaign.emailsSent)}</span>
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Submitted</p>
                            <p className="text-sm font-medium text-red-400">
                              {campaign.credentialsSubmitted}{" "}
                              <span className="text-xs">{pct(campaign.credentialsSubmitted, campaign.emailsSent)}</span>
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Reported</p>
                            <p className="text-sm font-medium text-green-400">
                              {campaign.reported}{" "}
                              <span className="text-xs">{pct(campaign.reported, campaign.emailsSent)}</span>
                            </p>
                          </div>
                        </div>
                      </div>
                      <div className="flex gap-1 ml-4">
                        {campaign.status === "draft" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => launchCampaignMutation.mutate(campaign.id)}
                            disabled={launchCampaignMutation.isPending}
                          >
                            <Play className="h-3 w-3 mr-1" /> Launch
                          </Button>
                        )}
                        {campaign.status === "running" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => completeCampaignMutation.mutate(campaign.id)}
                            disabled={completeCampaignMutation.isPending}
                          >
                            <Square className="h-3 w-3 mr-1" /> Complete
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

        {/* ── Templates ────────────────────────────────────────── */}
        <TabsContent value="templates" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">{templatesData?.total ?? 0} template(s)</p>
            <Dialog open={showAddTemplate} onOpenChange={setShowAddTemplate}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" /> New Template
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Create Phishing Template</DialogTitle>
                  <DialogDescription>Design a realistic phishing email template for campaigns</DialogDescription>
                </DialogHeader>
                <AddTemplateForm
                  onSubmit={(data) => createTemplateMutation.mutate(data)}
                  isPending={createTemplateMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>

          {(templatesData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No templates yet. Create spear-phishing templates for your industry.
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {templatesData?.items.map((template) => (
                <Card key={template.id}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        {categoryIcon(template.category)}
                        <p className="text-sm font-medium">{template.name}</p>
                      </div>
                      <Badge variant="outline" className={`${difficultyColor(template.difficulty)} text-xs`}>
                        {template.difficulty}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-2">Subject: {template.subject}</p>
                    {/* 68.4 — Template library with categorization */}
                    <div className="flex items-center gap-3 mt-2">
                      <Badge variant="outline" className="text-[10px]">
                        {formatLabel(template.category)}
                      </Badge>
                      {template.industry && (
                        <span className="text-xs text-muted-foreground">&middot; {template.industry}</span>
                      )}
                      <span className="text-xs text-muted-foreground">&middot; Used {template.usageCount}x</span>
                      {template.isBuiltIn && (
                        <Badge
                          variant="outline"
                          className="bg-blue-500/10 text-blue-400 border-blue-500/20 text-[10px]"
                        >
                          Built-in
                        </Badge>
                      )}
                    </div>
                    {template.successRate != null && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Success rate: {Math.round(template.successRate)}%
                      </p>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Risk Scores ──────────────────────────────────────── */}
        <TabsContent value="risk-scores" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search employees..."
                value={riskSearch}
                onChange={(e) => setRiskSearch(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>

          {(riskData?.items ?? []).length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No risk scores calculated yet. Scores are computed after phishing campaigns are completed.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {riskData?.items.map((emp) => (
                <Card key={emp.id}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold ${riskScoreBg(emp.riskScore)} ${riskScoreColor(emp.riskScore)}`}
                        >
                          {Math.round(emp.riskScore)}
                        </div>
                        <div>
                          <p className="text-sm font-medium">{emp.name || emp.email}</p>
                          <p className="text-xs text-muted-foreground">
                            {emp.email}
                            {emp.department ? ` — ${emp.department}` : ""}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {trendIcon(emp.riskTrend)}
                        <span className="text-xs text-muted-foreground">{formatLabel(emp.riskTrend)}</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-4 gap-4 mt-3">
                      <div>
                        <p className="text-xs text-muted-foreground">Click Rate</p>
                        <p className="text-sm font-medium text-orange-400">{Math.round(emp.phishingClickRate)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Report Rate</p>
                        <p className="text-sm font-medium text-green-400">{Math.round(emp.reportRate)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Training</p>
                        <p className="text-sm font-medium">
                          {emp.trainingsCompleted}/{emp.trainingsAssigned} complete
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Campaigns</p>
                        <p className="text-sm font-medium">{emp.campaignsReceived} received</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Training ─────────────────────────────────────────── */}
        <TabsContent value="training" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {modulesData?.total ?? 0} module(s), {assignmentsData?.total ?? 0} assignment(s)
            </p>
            <Dialog open={showAddModule} onOpenChange={setShowAddModule}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" /> New Module
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Training Module</DialogTitle>
                  <DialogDescription>Add security awareness training content to the library</DialogDescription>
                </DialogHeader>
                <AddModuleForm
                  onSubmit={(data) => createModuleMutation.mutate(data)}
                  isPending={createModuleMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>

          {/* Modules */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(modulesData?.items ?? []).map((module) => (
              <Card key={module.id}>
                <CardContent className="pt-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      {moduleTypeIcon(module.moduleType)}
                      <p className="text-sm font-medium">{module.title}</p>
                    </div>
                    <Badge variant="outline" className={`${difficultyColor(module.difficulty)} text-xs`}>
                      {module.difficulty}
                    </Badge>
                  </div>
                  {module.description && <p className="text-xs text-muted-foreground mt-2">{module.description}</p>}
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-xs text-muted-foreground">{formatLabel(module.category)}</span>
                    <span className="text-xs text-muted-foreground">&middot; {module.durationMinutes} min</span>
                    <span className="text-xs text-muted-foreground">&middot; {module.completionCount} completions</span>
                  </div>
                  {module.averageScore != null && (
                    <p className="text-xs text-muted-foreground mt-1">Avg score: {Math.round(module.averageScore)}%</p>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>

          {(modulesData?.items ?? []).length === 0 && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No training modules yet. Create videos, quizzes, and interactive simulations.
              </CardContent>
            </Card>
          )}

          {/* Assignments */}
          {(assignmentsData?.items ?? []).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Training Assignments</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {assignmentsData?.items.map((assignment) => (
                    <div
                      key={assignment.id}
                      className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                    >
                      <div>
                        <p className="text-sm font-medium">{assignment.employeeName || assignment.employeeEmail}</p>
                        <p className="text-xs text-muted-foreground">
                          {assignment.assignedReason ? formatLabel(assignment.assignedReason) : "Manual"} &middot;
                          {assignment.dueAt ? ` Due: ${formatDateTime(assignment.dueAt)}` : ""}
                        </p>
                        {/* 68.3 — Training assignment reason indicator */}
                        {assignment.assignedReason === "phishing_failure_remedial" && (
                          <Badge
                            variant="outline"
                            className="bg-orange-500/10 text-orange-400 border-orange-500/20 text-[10px] mt-1"
                          >
                            <AlertTriangle className="h-3 w-3 mr-0.5" /> Auto-assigned (phishing failure)
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {assignment.completedAt ? (
                          <Badge
                            variant="outline"
                            className="bg-green-500/10 text-green-400 border-green-500/20 text-xs"
                          >
                            <SuccessIcon size={12} color="#22c55e" /> {assignment.passed ? "Passed" : "Completed"}
                            {assignment.score != null ? ` (${assignment.score}%)` : ""}
                          </Badge>
                        ) : (
                          <Badge
                            variant="outline"
                            className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 text-xs"
                          >
                            <Clock className="h-3 w-3 mr-1" /> Pending
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Vishing ──────────────────────────────────────────── */}
        <TabsContent value="vishing" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Vishing Simulation</CardTitle>
              <CardDescription>
                Automated voice phishing (vishing) simulation. Test employees with realistic phone call scenarios to
                measure susceptibility to social engineering over the phone.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 border border-border/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Phone className="h-5 w-5 text-yellow-400" />
                    <p className="text-sm font-medium">IT Help Desk Impersonation</p>
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">
                    Automated call claiming to be IT support, requesting credentials for "urgent system update"
                  </p>
                  <Badge variant="outline" className={difficultyColor("medium")}>
                    Medium
                  </Badge>
                </div>
                <div className="p-4 border border-border/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Phone className="h-5 w-5 text-red-400" />
                    <p className="text-sm font-medium">Executive Impersonation</p>
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">
                    Caller claims to be a C-level executive requesting urgent wire transfer or data access
                  </p>
                  <Badge variant="outline" className={difficultyColor("hard")}>
                    Hard
                  </Badge>
                </div>
                <div className="p-4 border border-border/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Phone className="h-5 w-5 text-blue-400" />
                    <p className="text-sm font-medium">Vendor Callback Scam</p>
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">
                    Caller claims to be from a known vendor, requesting account verification or payment details
                  </p>
                  <Badge variant="outline" className={difficultyColor("medium")}>
                    Medium
                  </Badge>
                </div>
              </div>
              <p className="text-xs text-muted-foreground mt-4 text-center">
                Vishing simulation requires telephony integration (Twilio, AWS Connect). Configure in Settings to
                enable.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Forms ──────────────────────────────────────────────────────────

function AddCampaignForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("credential_harvest");
  const [subject, setSubject] = useState("");
  const [senderName, setSenderName] = useState("");
  const [senderEmail, setSenderEmail] = useState("");
  const [targetEmails, setTargetEmails] = useState("");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Campaign Name *</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Q1 Security Awareness Test" />
      </div>
      <div className="space-y-2">
        <Label>Description</Label>
        <Textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Quarterly phishing test for all departments"
        />
      </div>
      <div className="space-y-2">
        <Label>Template Category</Label>
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TEMPLATE_CATEGORIES.map((c) => (
              <SelectItem key={c} value={c}>
                {formatLabel(c)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-2">
        <Label>Email Subject</Label>
        <Input
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="Action Required: Update Your Password"
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Sender Name</Label>
          <Input value={senderName} onChange={(e) => setSenderName(e.target.value)} placeholder="IT Security" />
        </div>
        <div className="space-y-2">
          <Label>Sender Email</Label>
          <Input
            value={senderEmail}
            onChange={(e) => setSenderEmail(e.target.value)}
            placeholder="security@company.com"
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label>Target Emails (comma-separated)</Label>
        <Textarea
          value={targetEmails}
          onChange={(e) => setTargetEmails(e.target.value)}
          placeholder="user1@company.com, user2@company.com"
          rows={3}
        />
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              name,
              description: description || undefined,
              templateCategory: category,
              subject: subject || undefined,
              senderName: senderName || undefined,
              senderEmail: senderEmail || undefined,
              targetEmails: targetEmails
                .split(",")
                .map((e) => e.trim())
                .filter(Boolean),
            })
          }
          disabled={!name || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
          Create Campaign
        </Button>
      </DialogFooter>
    </div>
  );
}

function AddTemplateForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState("");
  const [category, setCategory] = useState("credential_harvest");
  const [difficulty, setDifficulty] = useState("medium");
  const [subject, setSubject] = useState("");
  const [senderName, setSenderName] = useState("");
  const [senderEmail, setSenderEmail] = useState("");
  const [emailBody, setEmailBody] = useState("");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Template Name *</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Password Reset — IT Dept" />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Category *</Label>
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TEMPLATE_CATEGORIES.map((c) => (
                <SelectItem key={c} value={c}>
                  {formatLabel(c)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Difficulty</Label>
          <Select value={difficulty} onValueChange={setDifficulty}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["easy", "medium", "hard", "expert"].map((d) => (
                <SelectItem key={d} value={d}>
                  {formatLabel(d)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-2">
        <Label>Subject *</Label>
        <Input
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="Your password will expire in 24 hours"
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Sender Name *</Label>
          <Input value={senderName} onChange={(e) => setSenderName(e.target.value)} placeholder="IT Support" />
        </div>
        <div className="space-y-2">
          <Label>Sender Email *</Label>
          <Input
            value={senderEmail}
            onChange={(e) => setSenderEmail(e.target.value)}
            placeholder="it-support@company.com"
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label>Email Body (HTML) *</Label>
        <Textarea
          value={emailBody}
          onChange={(e) => setEmailBody(e.target.value)}
          placeholder="<p>Dear user, your password...</p>"
          rows={5}
        />
      </div>
      <DialogFooter>
        <Button
          onClick={() => onSubmit({ name, category, difficulty, subject, senderName, senderEmail, emailBody })}
          disabled={!name || !subject || !senderName || !senderEmail || !emailBody || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
          Create Template
        </Button>
      </DialogFooter>
    </div>
  );
}

function AddModuleForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [moduleType, setModuleType] = useState("video");
  const [category, setCategory] = useState("phishing_awareness");
  const [difficulty, setDifficulty] = useState("beginner");
  const [duration, setDuration] = useState("15");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Title *</Label>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Recognizing Phishing Emails" />
      </div>
      <div className="space-y-2">
        <Label>Description</Label>
        <Textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Learn to identify common phishing tactics..."
        />
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>Type *</Label>
          <Select value={moduleType} onValueChange={setModuleType}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {MODULE_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {formatLabel(t)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Category *</Label>
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TRAINING_CATEGORIES.map((c) => (
                <SelectItem key={c} value={c}>
                  {formatLabel(c)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Difficulty</Label>
          <Select value={difficulty} onValueChange={setDifficulty}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["beginner", "intermediate", "advanced"].map((d) => (
                <SelectItem key={d} value={d}>
                  {formatLabel(d)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-2">
        <Label>Duration (minutes)</Label>
        <Input type="number" value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="15" />
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              title,
              description: description || undefined,
              moduleType,
              category,
              difficulty,
              durationMinutes: Number(duration) || 15,
            })
          }
          disabled={!title || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
          Create Module
        </Button>
      </DialogFooter>
    </div>
  );
}
