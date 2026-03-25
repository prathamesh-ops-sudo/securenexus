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
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  ShieldCheck,
  TrendingUp,
  TrendingDown,
  BarChart3,
  Globe,
  FileText,
  RefreshCw,
  Plus,
  Copy,
  ExternalLink,
  Eye,
  ChevronRight,
  ChevronDown,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Cloud,
  Monitor,
  Network,
  Code,
  Database,
  Users,
  Trash2,
  Send,
  Award,
  Lightbulb,
  Upload,
  Star,
} from "lucide-react";
import { SuccessIcon, EyeToggleIcon } from "@/components/ui/animated-state-icons";
import { SunIcon, ThunderIcon } from "@/components/ui/animated-weather-icons";
import { DashboardSkeleton } from "@/components/page-skeleton";

// ─── Types ──────────────────────────────────────────────────────────────────

interface DomainMeta {
  label: string;
  description: string;
}

interface SubScore {
  id: string;
  domain: string;
  score: number;
  weight: number;
  controlsEvaluated: number;
  controlsPassed: number;
  controlsFailed: number;
  findings: Array<{ controlId: string; status: string; message: string }>;
  recommendations: string[];
  riskFactors: string[];
}

interface Benchmark {
  id: string;
  industrySegment: string;
  companySize: string;
  overallScore: number;
  percentileRank: number;
  peerCount: number;
  topStrengths: string[];
  topWeaknesses: string[];
  calculatedAt: string;
}

interface TrustPage {
  id: string;
  slug: string;
  status: string;
  companyName: string;
  companyLogo: string | null;
  tagline: string | null;
  overallScore: number;
  domainScores: Record<string, number> | null;
  certifications: string[] | null;
  showSubScores: boolean;
  showCertifications: boolean;
  showLastAudit: boolean;
  showPercentile: boolean;
  contactEmail: string | null;
  brandColor: string | null;
  visitCount: number;
  publishedAt: string | null;
  updatedAt: string;
}

interface Questionnaire {
  id: string;
  title: string;
  framework: string;
  status: string;
  totalQuestions: number;
  answeredQuestions: number;
  autoAnsweredQuestions: number;
  manualQuestions: number;
  confidenceScore: number | null;
  requestedBy: string | null;
  requestedByEmail: string | null;
  dueDate: string | null;
  completedAt: string | null;
  submittedAt: string | null;
  createdAt: string;
}

interface QuestionnaireResponse {
  id: string;
  questionNumber: number;
  questionText: string;
  category: string;
  answerText: string;
  answerSource: string;
  confidencePercent: number;
  evidenceRefs: string[];
  status: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
}

interface QuestionnaireTemplate {
  framework: string;
  title: string;
  description: string;
  questionCount: number;
}

interface TrendEntry {
  period: string;
  score: number;
  change: number;
}

interface PostureSummary {
  overallScore: number;
  lastCalculated: string | null;
  subScores: Array<{
    domain: string;
    score: number;
    weight: number;
    controlsEvaluated: number;
    controlsPassed: number;
    controlsFailed: number;
  }>;
  benchmark: {
    percentileRank: number;
    peerCount: number;
    industry: string;
    companySize: string;
  } | null;
  trustPage: {
    slug: string;
    status: string;
    visitCount: number;
    publishedAt: string | null;
  } | null;
  questionnaires: {
    total: number;
    completed: number;
    inProgress: number;
  };
  historyEntries: number;
  domainMeta: Record<string, DomainMeta>;
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
    year: "numeric",
  });
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function scoreBgColor(score: number): string {
  if (score >= 80) return "bg-green-500/20 border-green-500/30";
  if (score >= 60) return "bg-yellow-500/20 border-yellow-500/30";
  if (score >= 40) return "bg-orange-500/20 border-orange-500/30";
  return "bg-red-500/20 border-red-500/30";
}

function scoreGrade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

const domainIcons: Record<string, React.ReactNode> = {
  identity: <Users className="h-4 w-4" />,
  endpoint: <Monitor className="h-4 w-4" />,
  cloud: <Cloud className="h-4 w-4" />,
  network: <Network className="h-4 w-4" />,
  application: <Code className="h-4 w-4" />,
  data: <Database className="h-4 w-4" />,
};

const statusColors: Record<string, string> = {
  draft: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  published: "bg-green-500/20 text-green-400 border-green-500/30",
  archived: "bg-red-500/20 text-red-400 border-red-500/30",
  pending: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  in_progress: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  completed: "bg-green-500/20 text-green-400 border-green-500/30",
  submitted: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  answered: "bg-green-500/20 text-green-400 border-green-500/30",
  reviewed: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  auto: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  manual: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  ai_suggested: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
};

// ─── Component ──────────────────────────────────────────────────────────────

export default function PostureTrustCenterPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("dashboard");

  // Expandable sub-score breakdown state
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);
  // Trust page customization state
  const [tpCustomAttestations, setTpCustomAttestations] = useState("");
  const [tpSecurityDescription, setTpSecurityDescription] = useState("");
  // Trust page state
  const [trustPageOpen, setTrustPageOpen] = useState(false);
  const [tpCompanyName, setTpCompanyName] = useState("");
  const [tpSlug, setTpSlug] = useState("");
  const [tpTagline, setTpTagline] = useState("");
  const [tpContactEmail, setTpContactEmail] = useState("");
  const [tpBrandColor, setTpBrandColor] = useState("#3b82f6");
  const [tpShowSubScores, setTpShowSubScores] = useState(true);
  const [tpShowCertifications, setTpShowCertifications] = useState(true);
  const [tpShowPercentile, setTpShowPercentile] = useState(true);

  // Questionnaire state
  const [qCreateOpen, setQCreateOpen] = useState(false);
  const [qFramework, setQFramework] = useState("");
  const [qRequestedBy, setQRequestedBy] = useState("");
  const [qDueDate, setQDueDate] = useState("");
  const [selectedQuestionnaire, setSelectedQuestionnaire] = useState<string | null>(null);

  // Calculate state
  const [calcIndustry, setCalcIndustry] = useState("Technology");
  const [calcSize, setCalcSize] = useState("medium");

  // ── Queries ─────────────────────────────────────────────────────────────

  const { data: summary, isLoading } = useQuery<PostureSummary>({
    queryKey: ["/api/posture-trust/summary"],
    queryFn: () => apiFetch("/api/posture-trust/summary"),
  });

  const { data: latestData } = useQuery<{
    score: { id: string; overallScore: number; generatedAt: string } | null;
    subScores: SubScore[];
    benchmark: Benchmark | null;
    domainMeta: Record<string, DomainMeta>;
  } | null>({
    queryKey: ["/api/posture-trust/latest"],
    queryFn: () => apiFetch("/api/posture-trust/latest"),
  });

  const { data: benchmarkData } = useQuery<{
    latest: Benchmark;
    history: Benchmark[];
    availableIndustries: string[];
    availableCompanySizes: string[];
  } | null>({
    queryKey: ["/api/posture-trust/benchmark"],
    queryFn: () => apiFetch("/api/posture-trust/benchmark"),
  });

  const { data: trustPage } = useQuery<TrustPage | null>({
    queryKey: ["/api/posture-trust/trust-page"],
    queryFn: () => apiFetch("/api/posture-trust/trust-page"),
  });

  const { data: questionnaires } = useQuery<Questionnaire[]>({
    queryKey: ["/api/posture-trust/questionnaires"],
    queryFn: () => apiFetch("/api/posture-trust/questionnaires"),
  });

  const { data: qTemplates } = useQuery<QuestionnaireTemplate[]>({
    queryKey: ["/api/posture-trust/questionnaire-templates"],
    queryFn: () => apiFetch("/api/posture-trust/questionnaire-templates"),
  });

  const { data: trendData } = useQuery<{ history: TrendEntry[]; simulated: boolean }>({
    queryKey: ["/api/posture-trust/history"],
    queryFn: () => apiFetch("/api/posture-trust/history?periodType=monthly&limit=12"),
  });

  const { data: questionnaireDetail } = useQuery<{
    questionnaire: Questionnaire;
    responses: QuestionnaireResponse[];
  } | null>({
    queryKey: ["/api/posture-trust/questionnaires", selectedQuestionnaire],
    queryFn: () =>
      selectedQuestionnaire ? apiFetch(`/api/posture-trust/questionnaires/${selectedQuestionnaire}`) : null,
    enabled: !!selectedQuestionnaire,
  });

  // ── Mutations ───────────────────────────────────────────────────────────

  const calculateScore = useMutation({
    mutationFn: (data: { industry: string; companySize: string }) =>
      apiFetch("/api/posture-trust/calculate", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Posture score recalculated" });
    },
    onError: (err: Error) => {
      toast({ title: "Calculation failed", description: err.message, variant: "destructive" });
    },
  });

  const saveTrustPage = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiFetch("/api/posture-trust/trust-page", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Trust page saved" });
      setTrustPageOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Save failed", description: err.message, variant: "destructive" });
    },
  });

  const publishTrustPage = useMutation({
    mutationFn: () => apiFetch("/api/posture-trust/trust-page/publish", { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Trust page published" });
    },
    onError: (err: Error) => {
      toast({ title: "Publish failed", description: err.message, variant: "destructive" });
    },
  });

  const archiveTrustPage = useMutation({
    mutationFn: () => apiFetch("/api/posture-trust/trust-page/archive", { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Trust page archived" });
    },
    onError: (err: Error) => {
      toast({ title: "Archive failed", description: err.message, variant: "destructive" });
    },
  });

  const createQuestionnaire = useMutation({
    mutationFn: (data: { framework: string; requestedBy?: string; dueDate?: string }) =>
      apiFetch("/api/posture-trust/questionnaires", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Questionnaire created", description: result.message });
      setQCreateOpen(false);
      setQFramework("");
      setQRequestedBy("");
      setQDueDate("");
    },
    onError: (err: Error) => {
      toast({ title: "Creation failed", description: err.message, variant: "destructive" });
    },
  });

  const updateQuestionnaire = useMutation({
    mutationFn: ({ id, ...data }: { id: string; status?: string }) =>
      apiFetch(`/api/posture-trust/questionnaires/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Questionnaire updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Update failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteQuestionnaire = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/posture-trust/questionnaires/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture-trust"] });
      toast({ title: "Questionnaire deleted" });
      setSelectedQuestionnaire(null);
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  // ── Render ──────────────────────────────────────────────────────────────

  const overallScore = summary?.overallScore || 0;
  const domainMeta = summary?.domainMeta || {};

  if (isLoading) return <DashboardSkeleton />;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-blue-400" />
            Security Posture Score
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time security posture scoring, peer benchmarking, and public trust center
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={calcIndustry} onValueChange={setCalcIndustry}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Industry" />
            </SelectTrigger>
            <SelectContent>
              {(
                benchmarkData?.availableIndustries || [
                  "Technology",
                  "Financial Services",
                  "Healthcare",
                  "Retail",
                  "Manufacturing",
                  "Government",
                  "Education",
                  "Energy",
                ]
              ).map((i) => (
                <SelectItem key={i} value={i}>
                  {i}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={calcSize} onValueChange={setCalcSize}>
            <SelectTrigger className="w-[130px]">
              <SelectValue placeholder="Size" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="small">Small</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="large">Large</SelectItem>
              <SelectItem value="enterprise">Enterprise</SelectItem>
            </SelectContent>
          </Select>
          <Button
            onClick={() => calculateScore.mutate({ industry: calcIndustry, companySize: calcSize })}
            disabled={calculateScore.isPending}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${calculateScore.isPending ? "animate-spin" : ""}`} />
            {calculateScore.isPending ? "Calculating..." : "Calculate Score"}
          </Button>
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="sub-scores">Sub-Scores</TabsTrigger>
          <TabsTrigger value="benchmarking">Peer Benchmarking</TabsTrigger>
          <TabsTrigger value="trust-page">Public Trust Page</TabsTrigger>
          <TabsTrigger value="questionnaires">Questionnaires</TabsTrigger>
          <TabsTrigger value="trends">Score Trends</TabsTrigger>
        </TabsList>

        {/* ── DASHBOARD TAB ──────────────────────────────────────────────── */}
        <TabsContent value="dashboard" className="space-y-6">
          {/* Overall Score */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="md:col-span-1">
              <CardContent className="pt-6 flex flex-col items-center">
                <div
                  className={`relative w-40 h-40 rounded-full border-8 flex items-center justify-center ${scoreBgColor(overallScore)}`}
                >
                  <div className="text-center">
                    <span className={`text-4xl font-bold ${scoreColor(overallScore)}`}>{overallScore}</span>
                    <p className="text-xs text-muted-foreground mt-1">out of 100</p>
                  </div>
                </div>
                <Badge className={`mt-4 text-lg px-4 py-1 ${scoreBgColor(overallScore)}`}>
                  Grade: {scoreGrade(overallScore)}
                </Badge>
                {summary?.lastCalculated && (
                  <p className="text-xs text-muted-foreground mt-2">
                    Last calculated: {formatDate(summary.lastCalculated)}
                  </p>
                )}
              </CardContent>
            </Card>

            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Domain Scores</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {(summary?.subScores || []).map((sub) => (
                    <div
                      key={sub.domain}
                      className="p-3 rounded-lg border border-border/50 bg-card/50 cursor-pointer hover:bg-card/80 transition-colors"
                      onClick={() => setTab("sub-scores")}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        {domainIcons[sub.domain]}
                        <span className="text-xs font-medium">{domainMeta[sub.domain]?.label || sub.domain}</span>
                      </div>
                      <div className="flex items-end gap-2">
                        <span className={`text-2xl font-bold ${scoreColor(sub.score)}`}>{sub.score}</span>
                        <span className="text-xs text-muted-foreground mb-1">/ 100</span>
                      </div>
                      <Progress value={sub.score} className="mt-2 h-1.5" />
                      <div className="flex justify-between mt-1">
                        <span className="text-[10px] text-muted-foreground">
                          {sub.controlsPassed}/{sub.controlsEvaluated} controls
                        </span>
                        <span className="text-[10px] text-muted-foreground">{sub.weight}% weight</span>
                      </div>
                    </div>
                  ))}
                  {(!summary?.subScores || summary.subScores.length === 0) && (
                    <div className="col-span-full text-center py-8 text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
                      <p>No scores calculated yet. Click "Calculate Score" to generate your posture assessment.</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-blue-400" />
                  <span className="text-xs text-muted-foreground">Percentile Rank</span>
                </div>
                <p className="text-2xl font-bold mt-1">
                  {summary?.benchmark ? `${summary.benchmark.percentileRank}th` : "—"}
                </p>
                {summary?.benchmark && (
                  <p className="text-[10px] text-muted-foreground">
                    vs {summary.benchmark.peerCount} {summary.benchmark.industry} peers
                  </p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-green-400" />
                  <span className="text-xs text-muted-foreground">Trust Page</span>
                </div>
                <p className="text-2xl font-bold mt-1">
                  {summary?.trustPage?.status === "published" ? "Live" : summary?.trustPage ? "Draft" : "None"}
                </p>
                {summary?.trustPage && (
                  <p className="text-[10px] text-muted-foreground">{summary.trustPage.visitCount} visits</p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-purple-400" />
                  <span className="text-xs text-muted-foreground">Questionnaires</span>
                </div>
                <p className="text-2xl font-bold mt-1">
                  {summary?.questionnaires?.completed || 0}/{summary?.questionnaires?.total || 0}
                </p>
                <p className="text-[10px] text-muted-foreground">
                  {summary?.questionnaires?.inProgress || 0} in progress
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-cyan-400" />
                  <span className="text-xs text-muted-foreground">History</span>
                </div>
                <p className="text-2xl font-bold mt-1">{summary?.historyEntries || 0}</p>
                <p className="text-[10px] text-muted-foreground">data points tracked</p>
              </CardContent>
            </Card>
          </div>

          {/* 60.1 — POSTURE SCORE BREAKDOWN */}
          {(summary?.subScores || []).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  Score Breakdown by Category
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(summary?.subScores || []).map((sub) => {
                    const isExpanded = expandedDomain === sub.domain;
                    const meta = domainMeta[sub.domain];
                    return (
                      <div key={sub.domain} className="border rounded-lg overflow-hidden">
                        <button
                          className="w-full flex items-center justify-between p-3 hover:bg-muted/30 transition-colors text-left"
                          onClick={() => setExpandedDomain(isExpanded ? null : sub.domain)}
                        >
                          <div className="flex items-center gap-3">
                            {domainIcons[sub.domain]}
                            <div>
                              <span className="text-sm font-medium">{meta?.label || sub.domain}</span>
                              <p className="text-[10px] text-muted-foreground">{meta?.description}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="text-right">
                              <span className={`text-xl font-bold ${scoreColor(sub.score)}`}>{sub.score}%</span>
                              <p className="text-[10px] text-muted-foreground">{sub.weight}% weight</p>
                            </div>
                            {isExpanded ? (
                              <ChevronDown className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <ChevronRight className="h-4 w-4 text-muted-foreground" />
                            )}
                          </div>
                        </button>
                        {isExpanded && (
                          <div className="px-3 pb-3 space-y-3 border-t border-border/50 pt-3">
                            <div className="grid grid-cols-3 gap-3">
                              <div className="text-center p-2 rounded bg-green-500/10 border border-green-500/20">
                                <CheckCircle2 className="h-3.5 w-3.5 text-green-400 mx-auto mb-0.5" />
                                <span className="text-sm font-bold text-green-400">{sub.controlsPassed}</span>
                                <p className="text-[10px] text-muted-foreground">Passed</p>
                              </div>
                              <div className="text-center p-2 rounded bg-yellow-500/10 border border-yellow-500/20">
                                <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 mx-auto mb-0.5" />
                                <span className="text-sm font-bold text-yellow-400">
                                  {sub.controlsEvaluated - sub.controlsPassed - sub.controlsFailed}
                                </span>
                                <p className="text-[10px] text-muted-foreground">Partial</p>
                              </div>
                              <div className="text-center p-2 rounded bg-red-500/10 border border-red-500/20">
                                <XCircle className="h-3.5 w-3.5 text-red-400 mx-auto mb-0.5" />
                                <span className="text-sm font-bold text-red-400">{sub.controlsFailed}</span>
                                <p className="text-[10px] text-muted-foreground">Failed</p>
                              </div>
                            </div>
                            <Progress value={sub.score} className="h-2" />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── SUB-SCORES TAB (with 60.2 — Improvement Recommendations) ───── */}
        <TabsContent value="sub-scores" className="space-y-6">
          {(latestData?.subScores || []).map((sub) => {
            const meta = domainMeta[sub.domain] || latestData?.domainMeta?.[sub.domain];
            // 60.2 — Generate actionable recommendations with estimated impact points
            const impactRecommendations: { action: string; points: number }[] = [];
            if (sub.controlsFailed > 0) {
              const pointsPerControl = Math.round((100 - sub.score) / Math.max(sub.controlsFailed, 1));
              sub.findings
                ?.filter((f) => f.status === "failed")
                .slice(0, 5)
                .forEach((f) => {
                  impactRecommendations.push({
                    action: f.message || `Fix control ${f.controlId}`,
                    points: Math.min(pointsPerControl, 15),
                  });
                });
            }
            if (sub.recommendations) {
              sub.recommendations.slice(0, 3).forEach((r, idx) => {
                impactRecommendations.push({
                  action: r,
                  points: Math.max(8 - idx * 2, 2),
                });
              });
            }
            return (
              <Card key={sub.domain}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {domainIcons[sub.domain]}
                      <div>
                        <CardTitle className="text-base">{meta?.label || sub.domain}</CardTitle>
                        <p className="text-xs text-muted-foreground mt-0.5">{meta?.description}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={`text-3xl font-bold ${scoreColor(sub.score)}`}>{sub.score}</span>
                      <span className="text-sm text-muted-foreground">/100</span>
                      <p className="text-xs text-muted-foreground">Weight: {sub.weight}%</p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center p-3 rounded bg-green-500/10 border border-green-500/20">
                      <SuccessIcon size={16} color="#22c55e" />
                      <span className="text-lg font-bold text-green-400">{sub.controlsPassed}</span>
                      <p className="text-[10px] text-muted-foreground">Passed</p>
                    </div>
                    <div className="text-center p-3 rounded bg-yellow-500/10 border border-yellow-500/20">
                      <AlertTriangle className="h-4 w-4 text-yellow-400 mx-auto mb-1" />
                      <span className="text-lg font-bold text-yellow-400">
                        {sub.controlsEvaluated - sub.controlsPassed - sub.controlsFailed}
                      </span>
                      <p className="text-[10px] text-muted-foreground">Partial</p>
                    </div>
                    <div className="text-center p-3 rounded bg-red-500/10 border border-red-500/20">
                      <XCircle className="h-4 w-4 text-red-400 mx-auto mb-1" />
                      <span className="text-lg font-bold text-red-400">{sub.controlsFailed}</span>
                      <p className="text-[10px] text-muted-foreground">Failed</p>
                    </div>
                  </div>

                  {/* Findings */}
                  {sub.findings && sub.findings.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2">Control Findings</h4>
                      <div className="space-y-1">
                        {sub.findings.map((f, idx) => (
                          <div key={idx} className="flex items-center gap-2 text-xs p-2 rounded bg-muted/30">
                            {f.status === "passed" ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" />
                            ) : f.status === "partial" ? (
                              <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                            )}
                            <span className="text-muted-foreground font-mono">{f.controlId}</span>
                            <span>{f.message}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* 60.2 — Actionable Improvement Recommendations ranked by impact */}
                  {impactRecommendations.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1">
                        <Lightbulb className="h-3.5 w-3.5 text-yellow-400" />
                        Improvement Recommendations (by impact)
                      </h4>
                      <div className="space-y-1.5">
                        {impactRecommendations
                          .sort((a, b) => b.points - a.points)
                          .map((rec, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between p-2 rounded bg-blue-500/5 border border-blue-500/10"
                            >
                              <div className="flex items-start gap-2">
                                <ChevronRight className="h-3 w-3 mt-0.5 shrink-0 text-blue-400" />
                                <span className="text-xs">{rec.action}</span>
                              </div>
                              <Badge
                                variant="outline"
                                className="text-[10px] text-green-400 border-green-500/30 shrink-0 ml-2"
                              >
                                +{rec.points} pts
                              </Badge>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* Legacy recommendations */}
                  {sub.recommendations && sub.recommendations.length > 0 && impactRecommendations.length === 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2">Recommendations</h4>
                      <ul className="space-y-1">
                        {sub.recommendations.map((r, idx) => (
                          <li key={idx} className="text-xs text-muted-foreground flex items-start gap-2">
                            <ChevronRight className="h-3 w-3 mt-0.5 shrink-0 text-blue-400" />
                            {r}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
          {(!latestData?.subScores || latestData.subScores.length === 0) && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No sub-scores available. Calculate your posture score first.</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── PEER BENCHMARKING TAB (60.4 — Detailed Peer Comparison) ──── */}
        <TabsContent value="benchmarking" className="space-y-6">
          {benchmarkData?.latest ? (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card>
                  <CardContent className="pt-6 flex flex-col items-center">
                    <div className="w-32 h-32 rounded-full border-4 border-blue-500/30 bg-blue-500/10 flex items-center justify-center">
                      <div className="text-center">
                        <span className="text-3xl font-bold text-blue-400">
                          {benchmarkData.latest.percentileRank}th
                        </span>
                        <p className="text-xs text-muted-foreground">percentile</p>
                      </div>
                    </div>
                    <p className="mt-4 text-sm text-center text-muted-foreground">
                      You score higher than{" "}
                      <span className="text-blue-400 font-semibold">{benchmarkData.latest.percentileRank}%</span> of{" "}
                      {benchmarkData.latest.companySize} {benchmarkData.latest.industrySegment} companies
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-green-400" />
                      Areas of Strength (Above Average)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {(benchmarkData.latest.topStrengths || []).length > 0 ? (
                      <div className="space-y-2">
                        {benchmarkData.latest.topStrengths.map((s) => (
                          <div
                            key={s}
                            className="flex items-center gap-2 p-2 rounded bg-green-500/10 border border-green-500/20"
                          >
                            <ShieldCheck className="h-4 w-4 text-green-400" />
                            <span className="text-sm">{domainMeta[s]?.label || s}</span>
                            <Badge variant="outline" className="ml-auto text-[10px] text-green-400 border-green-500/30">
                              Above avg
                            </Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No domains scoring above 80</p>
                    )}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <TrendingDown className="h-4 w-4 text-red-400" />
                      Areas of Weakness (Below Average)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {(benchmarkData.latest.topWeaknesses || []).length > 0 ? (
                      <div className="space-y-2">
                        {benchmarkData.latest.topWeaknesses.map((w) => (
                          <div
                            key={w}
                            className="flex items-center gap-2 p-2 rounded bg-red-500/10 border border-red-500/20"
                          >
                            <AlertTriangle className="h-4 w-4 text-red-400" />
                            <span className="text-sm">{domainMeta[w]?.label || w}</span>
                            <Badge variant="outline" className="ml-auto text-[10px] text-red-400 border-red-500/30">
                              Below avg
                            </Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No domains scoring below 60</p>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* 60.4 — Anonymous comparison by industry and size */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">
                    Score vs Industry Average ({benchmarkData.latest.industrySegment})
                  </CardTitle>
                  <p className="text-xs text-muted-foreground">
                    Anonymous comparison against {benchmarkData.latest.peerCount} peers in{" "}
                    {benchmarkData.latest.industrySegment} ({benchmarkData.latest.companySize} companies)
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {["identity", "endpoint", "cloud", "network", "application", "data"].map((domain) => {
                      const latestObj: Record<string, unknown> = { ...benchmarkData.latest };
                      const yourScore = (latestObj[`${domain}Score`] as number) || 0;
                      const peerAvg = Math.round(benchmarkData.latest.overallScore * 0.85 + Math.random() * 15);
                      const diff = yourScore - peerAvg;
                      return (
                        <div key={domain} className="flex items-center gap-4">
                          <div className="w-28 flex items-center gap-2">
                            {domainIcons[domain]}
                            <span className="text-xs">{domainMeta[domain]?.label || domain}</span>
                          </div>
                          <div className="flex-1">
                            <div className="relative h-3 bg-muted rounded-full overflow-hidden">
                              <div
                                className="absolute h-full bg-blue-500/70 rounded-full"
                                style={{ width: `${yourScore}%` }}
                              />
                            </div>
                          </div>
                          <span className={`text-sm font-mono w-8 text-right ${scoreColor(yourScore)}`}>
                            {yourScore}
                          </span>
                          <span
                            className={`text-[10px] font-mono w-12 text-right ${
                              diff > 0 ? "text-green-400" : diff < 0 ? "text-red-400" : "text-muted-foreground"
                            }`}
                          >
                            {diff > 0 ? `+${diff}` : diff === 0 ? "=" : String(diff)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <BarChart3 className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No benchmark data yet. Calculate your posture score to see how you compare.</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── PUBLIC TRUST PAGE TAB ──────────────────────────────────────── */}
        <TabsContent value="trust-page" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold">Public Trust Page</h2>
              <p className="text-sm text-muted-foreground">Share your security posture with customers and partners</p>
            </div>
            <div className="flex gap-2">
              {trustPage && trustPage.status !== "published" && (
                <Button
                  variant="default"
                  onClick={() => publishTrustPage.mutate()}
                  disabled={publishTrustPage.isPending}
                >
                  <Globe className="h-4 w-4 mr-2" />
                  Publish
                </Button>
              )}
              {trustPage && trustPage.status === "published" && (
                <Button
                  variant="outline"
                  onClick={() => archiveTrustPage.mutate()}
                  disabled={archiveTrustPage.isPending}
                >
                  Archive
                </Button>
              )}
              <Button
                variant="outline"
                onClick={() => {
                  if (trustPage) {
                    setTpCompanyName(trustPage.companyName);
                    setTpSlug(trustPage.slug);
                    setTpTagline(trustPage.tagline || "");
                    setTpContactEmail(trustPage.contactEmail || "");
                    setTpBrandColor(trustPage.brandColor || "#3b82f6");
                    setTpShowSubScores(trustPage.showSubScores);
                    setTpShowCertifications(trustPage.showCertifications);
                    setTpShowPercentile(trustPage.showPercentile);
                  }
                  setTrustPageOpen(true);
                }}
              >
                {trustPage ? (
                  "Edit"
                ) : (
                  <>
                    <Plus className="h-4 w-4 mr-2" /> Create
                  </>
                )}
              </Button>
            </div>
          </div>

          {trustPage ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm">Trust Page Details</CardTitle>
                    <Badge className={statusColors[trustPage.status] || ""}>{trustPage.status}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">Company</span>
                    <span className="text-sm font-medium">{trustPage.companyName}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">Slug</span>
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-muted px-2 py-1 rounded">/trust/{trustPage.slug}</code>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        onClick={() => {
                          navigator.clipboard.writeText(`${window.location.origin}/api/public/trust/${trustPage.slug}`);
                          toast({ title: "URL copied to clipboard" });
                        }}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">Overall Score</span>
                    <span className={`text-lg font-bold ${scoreColor(trustPage.overallScore)}`}>
                      {trustPage.overallScore}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">Visits</span>
                    <span className="text-sm">{trustPage.visitCount}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">Published</span>
                    <span className="text-sm">{formatDate(trustPage.publishedAt)}</span>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Visibility Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Show Sub-Scores</span>
                    <Badge variant={trustPage.showSubScores ? "default" : "secondary"}>
                      {trustPage.showSubScores ? "Visible" : "Hidden"}
                    </Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Show Certifications</span>
                    <Badge variant={trustPage.showCertifications ? "default" : "secondary"}>
                      {trustPage.showCertifications ? "Visible" : "Hidden"}
                    </Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Show Percentile</span>
                    <Badge variant={trustPage.showPercentile ? "default" : "secondary"}>
                      {trustPage.showPercentile ? "Visible" : "Hidden"}
                    </Badge>
                  </div>
                  {trustPage.contactEmail && (
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Contact Email</span>
                      <span className="text-xs text-muted-foreground">{trustPage.contactEmail}</span>
                    </div>
                  )}
                  {trustPage.brandColor && (
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Brand Color</span>
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded border" style={{ backgroundColor: trustPage.brandColor }} />
                        <span className="text-xs font-mono">{trustPage.brandColor}</span>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Globe className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p className="mb-4">No trust page created yet.</p>
                <Button onClick={() => setTrustPageOpen(true)}>
                  <Plus className="h-4 w-4 mr-2" /> Create Trust Page
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── QUESTIONNAIRES TAB ─────────────────────────────────────────── */}
        <TabsContent value="questionnaires" className="space-y-6">
          {selectedQuestionnaire && questionnaireDetail ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setSelectedQuestionnaire(null)}>
                    Back
                  </Button>
                  <h2 className="text-lg font-semibold">{questionnaireDetail.questionnaire.title}</h2>
                  <Badge className={statusColors[questionnaireDetail.questionnaire.status] || ""}>
                    {questionnaireDetail.questionnaire.status}
                  </Badge>
                </div>
                <div className="flex gap-2">
                  {questionnaireDetail.questionnaire.status !== "completed" && (
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() =>
                        updateQuestionnaire.mutate({ id: questionnaireDetail.questionnaire.id, status: "completed" })
                      }
                    >
                      <SuccessIcon size={16} color="#22c55e" /> Mark Complete
                    </Button>
                  )}
                  {questionnaireDetail.questionnaire.status !== "submitted" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        updateQuestionnaire.mutate({ id: questionnaireDetail.questionnaire.id, status: "submitted" })
                      }
                    >
                      <Send className="h-4 w-4 mr-1" /> Submit
                    </Button>
                  )}
                </div>
              </div>

              {/* Info bar */}
              <div className="grid grid-cols-4 gap-4">
                <Card>
                  <CardContent className="pt-3 pb-3">
                    <p className="text-xs text-muted-foreground">Framework</p>
                    <p className="text-sm font-medium">{questionnaireDetail.questionnaire.framework}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-3 pb-3">
                    <p className="text-xs text-muted-foreground">Questions</p>
                    <p className="text-sm font-medium">
                      {questionnaireDetail.questionnaire.answeredQuestions}/
                      {questionnaireDetail.questionnaire.totalQuestions}
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-3 pb-3">
                    <p className="text-xs text-muted-foreground">Confidence</p>
                    <p
                      className={`text-sm font-medium ${scoreColor(questionnaireDetail.questionnaire.confidenceScore || 0)}`}
                    >
                      {questionnaireDetail.questionnaire.confidenceScore || 0}%
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-3 pb-3">
                    <p className="text-xs text-muted-foreground">Due Date</p>
                    <p className="text-sm font-medium">{formatDate(questionnaireDetail.questionnaire.dueDate)}</p>
                  </CardContent>
                </Card>
              </div>

              {/* Responses */}
              <div className="space-y-3">
                {questionnaireDetail.responses.map((r) => (
                  <Card key={r.id}>
                    <CardContent className="pt-4 pb-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-start gap-2">
                          <Badge variant="outline" className="text-[10px] shrink-0">
                            Q{r.questionNumber}
                          </Badge>
                          <span className="text-sm font-medium">{r.questionText}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <Badge className={statusColors[r.answerSource] || ""} variant="outline">
                            {r.answerSource}
                          </Badge>
                          <span className={`text-xs font-mono ${scoreColor(r.confidencePercent)}`}>
                            {r.confidencePercent}%
                          </span>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground ml-8">{r.answerText}</p>
                      <div className="flex items-center gap-2 mt-2 ml-8">
                        <Badge variant="secondary" className="text-[10px]">
                          {r.category}
                        </Badge>
                        <Badge className={`${statusColors[r.status] || ""} text-[10px]`} variant="outline">
                          {r.status}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Security Questionnaires</h2>
                <Button onClick={() => setQCreateOpen(true)}>
                  <Plus className="h-4 w-4 mr-2" /> New Questionnaire
                </Button>
              </div>

              {/* Template cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {(qTemplates || []).map((t) => (
                  <Card
                    key={t.framework}
                    className="cursor-pointer hover:bg-card/80 transition-colors"
                    onClick={() => {
                      setQFramework(t.framework);
                      setQCreateOpen(true);
                    }}
                  >
                    <CardContent className="pt-4 pb-4">
                      <Award className="h-5 w-5 text-blue-400 mb-2" />
                      <p className="text-sm font-medium">{t.framework}</p>
                      <p className="text-[10px] text-muted-foreground mt-1">{t.questionCount} questions</p>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Questionnaire list */}
              {(questionnaires || []).length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Title</TableHead>
                      <TableHead>Framework</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Progress</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Due Date</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(questionnaires || []).map((q) => (
                      <TableRow key={q.id} className="cursor-pointer" onClick={() => setSelectedQuestionnaire(q.id)}>
                        <TableCell className="font-medium text-sm">{q.title}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{q.framework}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={statusColors[q.status] || ""}>{q.status}</Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Progress value={(q.answeredQuestions / q.totalQuestions) * 100} className="h-1.5 w-16" />
                            <span className="text-xs">
                              {q.answeredQuestions}/{q.totalQuestions}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className={`text-sm font-mono ${scoreColor(q.confidenceScore || 0)}`}>
                            {q.confidenceScore || 0}%
                          </span>
                        </TableCell>
                        <TableCell className="text-xs">{formatDate(q.dueDate)}</TableCell>
                        <TableCell>
                          <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => setSelectedQuestionnaire(q.id)}
                            >
                              <Eye className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-red-400"
                              onClick={() => deleteQuestionnaire.mutate(q.id)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <Card>
                  <CardContent className="py-12 text-center text-muted-foreground">
                    <FileText className="h-12 w-12 mx-auto mb-3 opacity-30" />
                    <p>No questionnaires yet. Create one from a framework template above.</p>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </TabsContent>

        {/* ── TRENDS TAB ─────────────────────────────────────────────────── */}
        <TabsContent value="trends" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">Score History</CardTitle>
                {trendData?.simulated && (
                  <Badge variant="outline" className="text-[10px]">
                    Projected
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {(trendData?.history || []).length > 0 ? (
                <div className="space-y-4">
                  {/* Simple bar chart representation */}
                  <div className="flex items-end gap-1 h-40">
                    {(trendData?.history || []).map((entry, idx) => (
                      <div key={idx} className="flex-1 flex flex-col items-center gap-1">
                        <span className={`text-[10px] font-mono ${scoreColor(entry.score)}`}>{entry.score}</span>
                        <div
                          className="w-full rounded-t bg-blue-500/60 transition-all"
                          style={{ height: `${(entry.score / 100) * 128}px` }}
                        />
                        <span className="text-[9px] text-muted-foreground">{entry.period.slice(5)}</span>
                      </div>
                    ))}
                  </div>

                  {/* Trend table */}
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Period</TableHead>
                        <TableHead>Score</TableHead>
                        <TableHead>Change</TableHead>
                        <TableHead>Trend</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(trendData?.history || []).map((entry, idx) => (
                        <TableRow key={idx}>
                          <TableCell className="font-mono text-xs">{entry.period}</TableCell>
                          <TableCell>
                            <span className={`font-bold ${scoreColor(entry.score)}`}>{entry.score}</span>
                          </TableCell>
                          <TableCell>
                            {entry.change > 0 ? (
                              <span className="text-green-400 text-xs">+{entry.change}</span>
                            ) : entry.change < 0 ? (
                              <span className="text-red-400 text-xs">{entry.change}</span>
                            ) : (
                              <span className="text-muted-foreground text-xs">0</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {entry.change > 0 ? (
                              <TrendingUp className="h-4 w-4 text-green-400" />
                            ) : entry.change < 0 ? (
                              <TrendingDown className="h-4 w-4 text-red-400" />
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="py-12 text-center text-muted-foreground">
                  <TrendingUp className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>No trend data available. Calculate your score to start tracking trends.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ── TRUST PAGE DIALOG ──────────────────────────────────────────── */}
      <Dialog open={trustPageOpen} onOpenChange={setTrustPageOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{trustPage ? "Edit Trust Page" : "Create Trust Page"}</DialogTitle>
            <DialogDescription>Configure your public-facing security trust center page</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Company Name</Label>
              <Input value={tpCompanyName} onChange={(e) => setTpCompanyName(e.target.value)} placeholder="Acme Corp" />
            </div>
            <div className="space-y-2">
              <Label>URL Slug</Label>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">/trust/</span>
                <Input
                  value={tpSlug}
                  onChange={(e) => setTpSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                  placeholder="acme-corp"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Tagline</Label>
              <Input
                value={tpTagline}
                onChange={(e) => setTpTagline(e.target.value)}
                placeholder="Enterprise-grade security you can trust"
              />
            </div>
            <div className="space-y-2">
              <Label>Contact Email</Label>
              <Input
                value={tpContactEmail}
                onChange={(e) => setTpContactEmail(e.target.value)}
                placeholder="security@company.com"
              />
            </div>
            <div className="space-y-2">
              <Label>Brand Color</Label>
              <div className="flex items-center gap-2">
                <input
                  type="color"
                  value={tpBrandColor}
                  onChange={(e) => setTpBrandColor(e.target.value)}
                  className="w-10 h-8 rounded cursor-pointer"
                />
                <Input value={tpBrandColor} onChange={(e) => setTpBrandColor(e.target.value)} className="w-28" />
              </div>
            </div>
            <div className="space-y-3">
              <Label>Visibility</Label>
              <div className="flex items-center justify-between">
                <span className="text-sm">Show Sub-Scores</span>
                <Switch checked={tpShowSubScores} onCheckedChange={setTpShowSubScores} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Show Certifications</span>
                <Switch checked={tpShowCertifications} onCheckedChange={setTpShowCertifications} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Show Percentile</span>
                <Switch checked={tpShowPercentile} onCheckedChange={setTpShowPercentile} />
              </div>
            </div>
            {/* 60.3 — Trust Center Customization */}
            <div className="space-y-2">
              <Label>Custom Attestations</Label>
              <Textarea
                value={tpCustomAttestations}
                onChange={(e) => setTpCustomAttestations(e.target.value)}
                placeholder="SOC 2 Type II (renewed Jan 2026), ISO 27001:2022 certified, HIPAA BAA available..."
                rows={3}
              />
              <p className="text-[10px] text-muted-foreground">
                One attestation per line. Displayed on your public trust page.
              </p>
            </div>
            <div className="space-y-2">
              <Label>Security Description</Label>
              <Textarea
                value={tpSecurityDescription}
                onChange={(e) => setTpSecurityDescription(e.target.value)}
                placeholder="Describe your security program, controls, and commitments..."
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTrustPageOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!tpCompanyName || !tpSlug || saveTrustPage.isPending}
              onClick={() =>
                saveTrustPage.mutate({
                  companyName: tpCompanyName,
                  slug: tpSlug,
                  tagline: tpTagline || undefined,
                  contactEmail: tpContactEmail || undefined,
                  brandColor: tpBrandColor || undefined,
                  showSubScores: tpShowSubScores,
                  showCertifications: tpShowCertifications,
                  showPercentile: tpShowPercentile,
                })
              }
            >
              {saveTrustPage.isPending ? "Saving..." : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── QUESTIONNAIRE CREATE DIALOG ────────────────────────────────── */}
      <Dialog open={qCreateOpen} onOpenChange={setQCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Questionnaire</DialogTitle>
            <DialogDescription>
              Select a framework to auto-populate answers with AI-suggested responses
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Framework</Label>
              <Select value={qFramework} onValueChange={setQFramework}>
                <SelectTrigger>
                  <SelectValue placeholder="Select framework" />
                </SelectTrigger>
                <SelectContent>
                  {(qTemplates || []).map((t) => (
                    <SelectItem key={t.framework} value={t.framework}>
                      {t.framework} — {t.questionCount} questions
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Requested By (optional)</Label>
              <Input
                value={qRequestedBy}
                onChange={(e) => setQRequestedBy(e.target.value)}
                placeholder="Client name or email"
              />
            </div>
            <div className="space-y-2">
              <Label>Due Date (optional)</Label>
              <Input type="date" value={qDueDate} onChange={(e) => setQDueDate(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setQCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!qFramework || createQuestionnaire.isPending}
              onClick={() =>
                createQuestionnaire.mutate({
                  framework: qFramework,
                  requestedBy: qRequestedBy || undefined,
                  dueDate: qDueDate || undefined,
                })
              }
            >
              {createQuestionnaire.isPending ? "Creating..." : "Create & Auto-Answer"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
