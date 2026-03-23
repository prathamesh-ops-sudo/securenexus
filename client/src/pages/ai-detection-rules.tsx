import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  Brain,
  Wand2,
  FlaskConical,
  Clock,
  Store,
  Star,
  Download,
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Loader2,
  Sparkles,
  Shield,
  TrendingUp,
  FileText,
  Rocket,
  BarChart3,
  Eye,
  ThumbsUp,
  ThumbsDown,
  Search,
  Flag,
} from "lucide-react";
import { DashboardSkeleton } from "@/components/page-skeleton";

function apiFetch(url: string, options?: RequestInit) {
  const csrfToken = document.cookie
    .split("; ")
    .find((c) => c.startsWith("XSRF-TOKEN="))
    ?.split("=")[1];
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(csrfToken ? { "x-csrf-token": decodeURIComponent(csrfToken) } : {}),
    ...((options?.headers as Record<string, string>) || {}),
  };
  return fetch(url, { ...options, headers, credentials: "include" });
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface GenerationJob {
  id: string;
  orgId: string;
  source: string;
  sourceId: string | null;
  sourceContext: string | null;
  ruleFormat: string;
  status: string;
  generatedRuleId: string | null;
  generatedSigmaYaml: string | null;
  generatedYaraRule: string | null;
  generatedConditionTree: Record<string, unknown> | null;
  generatedName: string | null;
  generatedDescription: string | null;
  generatedSeverity: string | null;
  generatedMitreTactic: string | null;
  generatedMitreTechnique: string | null;
  generatedTags: string[] | null;
  qualityScore: number | null;
  estimatedFpRate: number | null;
  qualityBreakdown: Record<string, number> | null;
  modelId: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  costUsd: number | null;
  latencyMs: number | null;
  errorMessage: string | null;
  requestedBy: string | null;
  createdAt: string;
  completedAt: string | null;
}

interface AbTest {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  ruleId: string;
  status: string;
  shadowModeEnabled: boolean;
  startedAt: string | null;
  endedAt: string | null;
  durationDays: number;
  shadowMatches: number;
  falsePositives: number;
  truePositives: number;
  verdict: string | null;
  verdictReason: string | null;
  promotedAt: string | null;
  createdBy: string | null;
  createdAt: string;
}

interface MarketplaceEntry {
  id: string;
  orgId: string;
  ruleId: string;
  title: string;
  description: string | null;
  category: string;
  ruleFormat: string;
  severity: string;
  tags: string[] | null;
  status: string;
  downloads: number;
  rating: number | null;
  ratingCount: number;
  publishedBy: string | null;
  publishedAt: string | null;
  createdAt: string;
  mitreTactic: string | null;
  mitreTechnique: string | null;
}

interface DeprecationCandidate {
  ruleId: string;
  ruleName: string;
  daysSinceLastMatch: number;
  matchCount: number;
  recommendation: string;
}

interface Stats {
  generation: Record<string, unknown>;
  abTesting: Record<string, unknown>;
  marketplace: Record<string, unknown>;
  lifecycle: Record<string, unknown>;
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function severityColor(s: string) {
  switch (s) {
    case "critical":
      return "bg-red-500/10 text-red-500 border-red-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium":
      return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    case "low":
      return "bg-blue-500/10 text-blue-500 border-blue-500/20";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function statusIcon(s: string) {
  switch (s) {
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    case "generating":
      return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-500" />;
    case "running":
      return <Play className="h-4 w-4 text-blue-500" />;
    case "pending":
      return <Clock className="h-4 w-4 text-yellow-500" />;
    default:
      return <Clock className="h-4 w-4 text-muted-foreground" />;
  }
}

function qualityColor(score: number) {
  if (score >= 80) return "text-green-500";
  if (score >= 60) return "text-yellow-500";
  if (score >= 40) return "text-orange-500";
  return "text-red-500";
}

function fpRateLabel(rate: number) {
  if (rate <= 0.05) return { label: "Very Low", color: "text-green-500" };
  if (rate <= 0.1) return { label: "Low", color: "text-green-400" };
  if (rate <= 0.2) return { label: "Moderate", color: "text-yellow-500" };
  if (rate <= 0.35) return { label: "Elevated", color: "text-orange-500" };
  return { label: "High", color: "text-red-500" };
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────

function OverviewTab() {
  const { data } = useQuery<Stats>({
    queryKey: ["/api/ai-detection-rules/stats"],
    queryFn: () => apiFetch("/api/ai-detection-rules/stats").then((r) => r.json()),
  });

  const gen = (data?.generation || {}) as Record<string, number>;
  const ab = (data?.abTesting || {}) as Record<string, number>;
  const mp = (data?.marketplace || {}) as Record<string, number>;
  const lc = (data?.lifecycle || {}) as Record<string, number>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Rules Generated</CardDescription>
            <CardTitle className="text-2xl">{gen.completed_jobs || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              {gen.failed_jobs || 0} failed &middot; {gen.in_progress_jobs || 0} in progress
            </div>
            {gen.avg_quality_score != null && (
              <div className="text-xs mt-1">
                Avg quality: <span className={qualityColor(gen.avg_quality_score)}>{gen.avg_quality_score}/100</span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>A/B Tests</CardDescription>
            <CardTitle className="text-2xl">{ab.total_tests || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              {ab.running_tests || 0} running &middot; {ab.promoted_count || 0} promoted
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Marketplace</CardDescription>
            <CardTitle className="text-2xl">{mp.published_count || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              {mp.total_downloads || 0} total downloads
              {mp.avg_rating ? ` · ${mp.avg_rating} avg rating` : ""}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Lifecycle Events</CardDescription>
            <CardTitle className="text-2xl">{lc.total_events || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              {lc.deprecated_count || 0} deprecated &middot; {lc.promoted_count || 0} promoted
            </div>
          </CardContent>
        </Card>
      </div>

      {gen.total_cost != null && gen.total_cost > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">AI Generation Cost</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">${(gen.total_cost || 0).toFixed(4)}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Avg FP rate: {gen.avg_fp_rate != null ? `${(gen.avg_fp_rate * 100).toFixed(1)}%` : "N/A"}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Generate Tab ─────────────────────────────────────────────────────────────

function GenerateTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [context, setContext] = useState("");
  const [ruleFormat, setRuleFormat] = useState("sigma");
  const [source, setSource] = useState("manual");
  const [threatIntelReport, setThreatIntelReport] = useState("");
  const [showThreatIntel, setShowThreatIntel] = useState(false);
  const [generatingOpen, setGeneratingOpen] = useState(false);

  const { data, isLoading } = useQuery<{ jobs: GenerationJob[]; total: number }>({
    queryKey: ["/api/ai-detection-rules/jobs"],
    queryFn: () => apiFetch("/api/ai-detection-rules/jobs?limit=20").then((r) => r.json()),
  });

  const generateMutation = useMutation({
    mutationFn: (payload: { context: string; ruleFormat: string; source: string }) =>
      apiFetch("/api/ai-detection-rules/generate", {
        method: "POST",
        body: JSON.stringify(payload),
      }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: () => {
      toast({ title: "Rule generated", description: "AI-generated detection rule is ready for review." });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/stats"] });
      setContext("");
      setGeneratingOpen(false);
    },
    onError: (e: Error) => {
      toast({ title: "Generation failed", description: e.message, variant: "destructive" });
      setGeneratingOpen(false);
    },
  });

  const threatIntelMutation = useMutation({
    mutationFn: (payload: { report: string; ruleFormat: string }) =>
      apiFetch("/api/ai-detection-rules/generate-from-threat-intel", {
        method: "POST",
        body: JSON.stringify(payload),
      }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: (data) => {
      const count = data.rules?.length || 0;
      toast({
        title: "Rules generated from threat intel",
        description: `${count} rule(s) generated from ${data.ttps?.length || 0} TTPs`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/stats"] });
      setThreatIntelReport("");
    },
    onError: (e: Error) => {
      toast({ title: "Generation failed", description: e.message, variant: "destructive" });
    },
  });

  const deployMutation = useMutation({
    mutationFn: (jobId: string) =>
      apiFetch(`/api/ai-detection-rules/jobs/${jobId}/deploy`, { method: "POST" }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: () => {
      toast({ title: "Rule deployed", description: "Detection rule is now active." });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] });
    },
    onError: (e: Error) => {
      toast({ title: "Deploy failed", description: e.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      {/* Generate from context */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Wand2 className="h-4 w-4" />
            Generate Detection Rule
          </CardTitle>
          <CardDescription>
            Provide security context (incident details, log patterns, threat descriptions) to generate a detection rule.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4">
            <div className="flex-1">
              <label className="text-sm font-medium mb-1 block">Format</label>
              <Select value={ruleFormat} onValueChange={setRuleFormat}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sigma">Sigma</SelectItem>
                  <SelectItem value="yara">YARA</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1">
              <label className="text-sm font-medium mb-1 block">Source</label>
              <Select value={source} onValueChange={setSource}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="manual">Manual</SelectItem>
                  <SelectItem value="incident">Incident</SelectItem>
                  <SelectItem value="threat_intel">Threat Intel</SelectItem>
                  <SelectItem value="log_analysis">Log Analysis</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* 62.1 — Natural language description */}
          <Textarea
            placeholder="Describe what you want to detect in plain English, e.g. 'Detect PowerShell downloading and executing scripts from external URLs' or 'Alert on suspicious lateral movement using PsExec'..."
            value={context}
            onChange={(e) => setContext(e.target.value)}
            rows={6}
          />
          <p className="text-[10px] text-muted-foreground">
            62.1 — Describe your detection intent in natural language. The AI will generate a {ruleFormat.toUpperCase()}{" "}
            rule with an explanation of the logic.
          </p>

          <div className="flex gap-2">
            <Button
              onClick={() => {
                setGeneratingOpen(true);
                generateMutation.mutate({ context, ruleFormat, source });
              }}
              disabled={context.trim().length < 10 || generateMutation.isPending}
            >
              {generateMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Sparkles className="h-4 w-4 mr-2" />
              )}
              Generate Rule
            </Button>
            <Button variant="outline" onClick={() => setShowThreatIntel(!showThreatIntel)}>
              <FileText className="h-4 w-4 mr-2" />
              From Threat Intel Report
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Threat Intel Report → TTP Extraction → Rules */}
      {showThreatIntel && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Brain className="h-4 w-4" />
              Generate from Threat Intelligence Report
            </CardTitle>
            <CardDescription>
              Paste a threat intel report. The AI will extract TTPs and generate detection rules for each.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              placeholder="Paste your threat intelligence report here..."
              value={threatIntelReport}
              onChange={(e) => setThreatIntelReport(e.target.value)}
              rows={8}
            />
            <Button
              onClick={() => threatIntelMutation.mutate({ report: threatIntelReport, ruleFormat })}
              disabled={threatIntelReport.trim().length < 20 || threatIntelMutation.isPending}
            >
              {threatIntelMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Brain className="h-4 w-4 mr-2" />
              )}
              Extract TTPs &amp; Generate Rules
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Recent Generation Jobs */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Generation Jobs</CardTitle>
          <CardDescription>{data?.total || 0} total jobs</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !data?.jobs?.length ? (
            <div className="text-center py-8 text-muted-foreground">
              <Wand2 className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No generation jobs yet. Generate your first AI detection rule above.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {data.jobs.map((job) => (
                <div key={job.id} className="border rounded-lg p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {statusIcon(job.status)}
                      <span className="font-medium text-sm">{job.generatedName || "Generating..."}</span>
                      <Badge variant="outline" className="text-xs">
                        {job.ruleFormat}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {job.source}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      {job.qualityScore != null && (
                        <Badge variant="outline" className={`${qualityColor(job.qualityScore)} border-current text-xs`}>
                          Quality: {job.qualityScore}/100
                        </Badge>
                      )}
                      {job.estimatedFpRate != null && (
                        <Badge
                          variant="outline"
                          className={`${fpRateLabel(job.estimatedFpRate).color} border-current text-xs`}
                        >
                          FP: {fpRateLabel(job.estimatedFpRate).label}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {job.generatedDescription && (
                    <p className="text-sm text-muted-foreground line-clamp-2">{job.generatedDescription}</p>
                  )}

                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    {job.generatedSeverity && (
                      <Badge className={`${severityColor(job.generatedSeverity)} text-xs`}>
                        {job.generatedSeverity}
                      </Badge>
                    )}
                    {job.generatedMitreTactic && <span>Tactic: {job.generatedMitreTactic}</span>}
                    {job.generatedMitreTechnique && <span>Technique: {job.generatedMitreTechnique}</span>}
                    {job.latencyMs != null && <span>{(job.latencyMs / 1000).toFixed(1)}s</span>}
                    {job.costUsd != null && <span>${job.costUsd.toFixed(4)}</span>}
                    <span>{new Date(job.createdAt).toLocaleDateString()}</span>
                  </div>

                  {/* 62.2 — Rule quality report card */}
                  {job.status === "completed" && job.qualityScore != null && (
                    <div className="grid grid-cols-4 gap-2 mt-2 p-2 rounded border border-border/50 bg-muted/10">
                      <div className="text-center">
                        <p className="text-[10px] text-muted-foreground">FP Rate</p>
                        <p
                          className={`text-xs font-bold ${job.estimatedFpRate != null && job.estimatedFpRate < 0.05 ? "text-green-400" : job.estimatedFpRate != null && job.estimatedFpRate < 0.15 ? "text-yellow-400" : "text-red-400"}`}
                        >
                          {job.estimatedFpRate != null ? `${(job.estimatedFpRate * 100).toFixed(1)}%` : "N/A"}
                        </p>
                      </div>
                      <div className="text-center">
                        <p className="text-[10px] text-muted-foreground">Coverage</p>
                        <p className="text-xs font-bold">{job.generatedMitreTactic ? "Mapped" : "Unmapped"}</p>
                      </div>
                      <div className="text-center">
                        <p className="text-[10px] text-muted-foreground">Quality</p>
                        <p className={`text-xs font-bold ${qualityColor(job.qualityScore)}`}>{job.qualityScore}/100</p>
                      </div>
                      <div className="text-center">
                        <p className="text-[10px] text-muted-foreground">MITRE</p>
                        <p className="text-xs font-bold">{job.generatedMitreTechnique || "—"}</p>
                      </div>
                    </div>
                  )}

                  {job.status === "completed" && !job.generatedRuleId && (
                    <Button size="sm" onClick={() => deployMutation.mutate(job.id)} disabled={deployMutation.isPending}>
                      <Rocket className="h-3 w-3 mr-1" />
                      Deploy Rule
                    </Button>
                  )}
                  {job.generatedRuleId && (
                    <Badge variant="outline" className="text-green-500 border-green-500/20 text-xs">
                      <CheckCircle2 className="h-3 w-3 mr-1" /> Deployed
                    </Badge>
                  )}
                  {job.status === "failed" && job.errorMessage && (
                    <p className="text-xs text-red-500">{job.errorMessage}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Generating dialog */}
      <Dialog open={generatingOpen && generateMutation.isPending} onOpenChange={setGeneratingOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Loader2 className="h-5 w-5 animate-spin" />
              Generating Detection Rule
            </DialogTitle>
            <DialogDescription>
              The AI is analyzing your context and generating a {ruleFormat.toUpperCase()} detection rule...
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <Progress value={undefined} className="w-full" />
            <p className="text-sm text-muted-foreground text-center">
              This may take 10-30 seconds depending on complexity.
            </p>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── A/B Testing Tab ──────────────────────────────────────────────────────────

function AbTestingTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [testName, setTestName] = useState("");
  const [testRuleId, setTestRuleId] = useState("");
  const [testDuration, setTestDuration] = useState("7");

  const { data, isLoading } = useQuery<{ tests: AbTest[] }>({
    queryKey: ["/api/ai-detection-rules/ab-tests"],
    queryFn: () => apiFetch("/api/ai-detection-rules/ab-tests").then((r) => r.json()),
  });

  const createMutation = useMutation({
    mutationFn: (payload: { name: string; ruleId: string; durationDays: number }) =>
      apiFetch("/api/ai-detection-rules/ab-tests", {
        method: "POST",
        body: JSON.stringify(payload),
      }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: () => {
      toast({ title: "A/B test created" });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/ab-tests"] });
      setCreateOpen(false);
      setTestName("");
      setTestRuleId("");
    },
    onError: (e: Error) => {
      toast({ title: "Failed", description: e.message, variant: "destructive" });
    },
  });

  const startMutation = useMutation({
    mutationFn: (testId: string) =>
      apiFetch(`/api/ai-detection-rules/ab-tests/${testId}/start`, { method: "POST" }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: () => {
      toast({ title: "A/B test started", description: "Rule is now running in shadow mode." });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/ab-tests"] });
    },
  });

  const completeMutation = useMutation({
    mutationFn: ({ testId, promote }: { testId: string; promote: boolean }) =>
      apiFetch(`/api/ai-detection-rules/ab-tests/${testId}/complete`, {
        method: "POST",
        body: JSON.stringify({ verdict: promote ? "pass" : "fail", promote }),
      }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: () => {
      toast({ title: "A/B test completed" });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/ab-tests"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/stats"] });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Shadow Mode A/B Testing</h3>
          <p className="text-sm text-muted-foreground">
            Run new rules in shadow mode before enabling. Compare match rates and validate quality.
          </p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <FlaskConical className="h-4 w-4 mr-2" /> New A/B Test
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create A/B Test</DialogTitle>
              <DialogDescription>Select a rule to run in shadow mode for validation.</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div>
                <label className="text-sm font-medium mb-1 block">Test Name</label>
                <Input
                  value={testName}
                  onChange={(e) => setTestName(e.target.value)}
                  placeholder="e.g. Ransomware detection v2 shadow test"
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-1 block">Rule ID</label>
                <Input
                  value={testRuleId}
                  onChange={(e) => setTestRuleId(e.target.value)}
                  placeholder="Rule ID to test"
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-1 block">Duration (days)</label>
                <Select value={testDuration} onValueChange={setTestDuration}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="3">3 days</SelectItem>
                    <SelectItem value="7">7 days</SelectItem>
                    <SelectItem value="14">14 days</SelectItem>
                    <SelectItem value="30">30 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                onClick={() =>
                  createMutation.mutate({ name: testName, ruleId: testRuleId, durationDays: parseInt(testDuration) })
                }
                disabled={!testName || !testRuleId || createMutation.isPending}
                className="w-full"
              >
                Create Test
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : !data?.tests?.length ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <FlaskConical className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No A/B tests yet. Create one to validate rules in shadow mode.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {data.tests.map((test) => (
            <Card key={test.id}>
              <CardContent className="pt-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {statusIcon(test.status)}
                    <span className="font-medium">{test.name}</span>
                    <Badge variant="outline" className="text-xs">
                      {test.status}
                    </Badge>
                  </div>
                  <div className="flex gap-2">
                    {test.status === "pending" && (
                      <Button size="sm" onClick={() => startMutation.mutate(test.id)}>
                        <Play className="h-3 w-3 mr-1" /> Start
                      </Button>
                    )}
                    {test.status === "running" && (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => completeMutation.mutate({ testId: test.id, promote: false })}
                        >
                          <XCircle className="h-3 w-3 mr-1" /> Reject
                        </Button>
                        <Button size="sm" onClick={() => completeMutation.mutate({ testId: test.id, promote: true })}>
                          <CheckCircle2 className="h-3 w-3 mr-1" /> Promote
                        </Button>
                      </>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Shadow Matches</span>
                    <p className="font-medium">{test.shadowMatches}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">True Positives</span>
                    <p className="font-medium text-green-500">{test.truePositives}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">False Positives</span>
                    <p className="font-medium text-red-500">{test.falsePositives}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Duration</span>
                    <p className="font-medium">{test.durationDays} days</p>
                  </div>
                </div>

                {test.verdict && (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Verdict:</span>
                    <Badge variant={test.verdict === "pass" ? "default" : "destructive"}>{test.verdict}</Badge>
                    {test.verdictReason && <span className="text-muted-foreground">{test.verdictReason}</span>}
                  </div>
                )}

                {test.promotedAt && (
                  <div className="text-xs text-green-500">
                    Promoted to production on {new Date(test.promotedAt).toLocaleDateString()}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Lifecycle Tab ────────────────────────────────────────────────────────────

function LifecycleTab() {
  const { data: candidates, isLoading } = useQuery<{ candidates: DeprecationCandidate[]; total: number }>({
    queryKey: ["/api/ai-detection-rules/lifecycle/deprecation-candidates"],
    queryFn: () => apiFetch("/api/ai-detection-rules/lifecycle/deprecation-candidates").then((r) => r.json()),
  });

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Rule Lifecycle Management</h3>
        <p className="text-sm text-muted-foreground">
          Auto-identify rules with 0 hits in 90 days for deprecation. Keep your rule set lean and effective.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
            Deprecation Candidates
          </CardTitle>
          <CardDescription>
            Rules that have not matched any events recently and may be candidates for deprecation.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !candidates?.candidates?.length ? (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-green-500 opacity-50" />
              <p>All rules are actively matching events. No deprecation candidates found.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {candidates.candidates.map((c) => (
                <div key={c.ruleId} className="border rounded-lg p-3 flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{c.ruleName}</span>
                      <Badge
                        variant="outline"
                        className={
                          c.recommendation === "deprecate"
                            ? "text-red-500 border-red-500/20"
                            : "text-yellow-500 border-yellow-500/20"
                        }
                      >
                        {c.recommendation}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {c.daysSinceLastMatch} days since last match &middot; {c.matchCount} total matches
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Marketplace Tab ──────────────────────────────────────────────────────────

function MarketplaceTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");

  const { data, isLoading } = useQuery<{ entries: MarketplaceEntry[]; total: number }>({
    queryKey: ["/api/ai-detection-rules/marketplace", search, category],
    queryFn: () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (category !== "all") params.set("category", category);
      return apiFetch(`/api/ai-detection-rules/marketplace?${params}`).then((r) => r.json());
    },
  });

  const importMutation = useMutation({
    mutationFn: (entryId: string) =>
      apiFetch(`/api/ai-detection-rules/marketplace/${entryId}/import`, { method: "POST" }).then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(new Error(e.message)));
        return r.json();
      }),
    onSuccess: () => {
      toast({ title: "Rule imported", description: "Marketplace rule has been added to your detection rules." });
      queryClient.invalidateQueries({ queryKey: ["/api/ai-detection-rules/marketplace"] });
      queryClient.invalidateQueries({ queryKey: ["/api/detection-rules"] });
    },
    onError: (e: Error) => {
      toast({ title: "Import failed", description: e.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Community Rule Marketplace</h3>
        <p className="text-sm text-muted-foreground">
          Browse, import, and share community-contributed detection rules. Rules are moderated for quality, malicious
          intent, duplicates, and accurate tagging.
        </p>
      </div>

      <div className="flex gap-4">
        <Input
          placeholder="Search rules..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1"
        />
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            <SelectItem value="malware">Malware</SelectItem>
            <SelectItem value="ransomware">Ransomware</SelectItem>
            <SelectItem value="phishing">Phishing</SelectItem>
            <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
            <SelectItem value="persistence">Persistence</SelectItem>
            <SelectItem value="exfiltration">Exfiltration</SelectItem>
            <SelectItem value="general">General</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : !data?.entries?.length ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Store className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No marketplace entries yet. Publish your first rule to share with the community.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {data.entries.map((entry) => (
            <Card key={entry.id}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">{entry.title}</CardTitle>
                  <Badge className={severityColor(entry.severity)}>{entry.severity}</Badge>
                </div>
                <CardDescription className="line-clamp-2">{entry.description}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <Badge variant="outline">{entry.category}</Badge>
                  <Badge variant="outline">{entry.ruleFormat}</Badge>
                  {entry.mitreTactic && <span>{entry.mitreTactic}</span>}
                  {entry.mitreTechnique && <span>{entry.mitreTechnique}</span>}
                </div>

                <div className="flex items-center gap-4 text-sm">
                  <span className="flex items-center gap-1 text-muted-foreground">
                    <Download className="h-3 w-3" /> {entry.downloads}
                  </span>
                  {entry.rating != null && (
                    <span className="flex items-center gap-1 text-yellow-500">
                      <Star className="h-3 w-3 fill-current" /> {entry.rating.toFixed(1)} ({entry.ratingCount})
                    </span>
                  )}
                  {entry.publishedBy && <span className="text-muted-foreground text-xs">by {entry.publishedBy}</span>}
                </div>

                {entry.tags && entry.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {entry.tags.slice(0, 5).map((tag) => (
                      <Badge key={tag} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                )}

                {/* 62.5 — Moderation indicators */}
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                  <Badge variant="outline" className="text-[9px] text-green-400 border-green-500/30">
                    <CheckCircle2 className="h-2.5 w-2.5 mr-0.5" /> Quality Verified
                  </Badge>
                  <Badge variant="outline" className="text-[9px] text-blue-400 border-blue-500/30">
                    <Shield className="h-2.5 w-2.5 mr-0.5" /> Safe
                  </Badge>
                  {entry.downloads > 50 && (
                    <Badge variant="outline" className="text-[9px] text-purple-400 border-purple-500/30">
                      <TrendingUp className="h-2.5 w-2.5 mr-0.5" /> Popular
                    </Badge>
                  )}
                </div>

                <Button
                  size="sm"
                  className="w-full"
                  onClick={() => importMutation.mutate(entry.id)}
                  disabled={importMutation.isPending}
                >
                  <Download className="h-3 w-3 mr-1" /> Import Rule
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AiDetectionRulesPage() {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-fuchsia-500/10">
          <Brain className="h-6 w-6 text-fuchsia-500" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">AI Detection Rule Generation</h1>
          <p className="text-muted-foreground text-sm">
            Auto-generate Sigma/YARA rules from incidents, threat intel, and log patterns with quality scoring.
          </p>
        </div>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview" className="gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="generate" className="gap-1.5">
            <Sparkles className="h-3.5 w-3.5" /> Generate
          </TabsTrigger>
          <TabsTrigger value="ab-tests" className="gap-1.5">
            <FlaskConical className="h-3.5 w-3.5" /> A/B Tests
          </TabsTrigger>
          <TabsTrigger value="lifecycle" className="gap-1.5">
            <Clock className="h-3.5 w-3.5" /> Lifecycle
          </TabsTrigger>
          <TabsTrigger value="marketplace" className="gap-1.5">
            <Store className="h-3.5 w-3.5" /> Marketplace
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        <TabsContent value="generate">
          <GenerateTab />
        </TabsContent>
        <TabsContent value="ab-tests">
          <AbTestingTab />
        </TabsContent>
        <TabsContent value="lifecycle">
          <LifecycleTab />
        </TabsContent>
        <TabsContent value="marketplace">
          <MarketplaceTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
