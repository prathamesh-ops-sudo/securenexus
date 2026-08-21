import { useQuery, useMutation } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient, ensureArray } from "@/lib/queryClient";
import { formatDateTime as formatTimestamp } from "@/lib/i18n";
import { Progress } from "@/components/ui/progress";
import {
  Shield,
  Cloud,
  Monitor,
  FileCheck,
  Brain,
  Globe,
  Server,
  Lock,
  Save,
  RefreshCw,
  TrendingUp,
  AlertTriangle,
  Bug,
  Clock,
  Users,
  CheckCircle,
  XCircle,
  Target,
  BarChart3,
  Layers,
  Activity,
  Network,
  Wrench,
  Search,
} from "lucide-react";
import { LockUnlockIcon } from "@/components/ui/animated-state-icons";

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-500";
  if (score >= 60) return "text-yellow-500";
  if (score >= 40) return "text-orange-500";
  return "text-red-500";
}

function scoreStrokeColor(score: number): string {
  if (score >= 80) return "stroke-green-500";
  if (score >= 60) return "stroke-yellow-500";
  if (score >= 40) return "stroke-orange-500";
  return "stroke-red-500";
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Excellent";
  if (score >= 60) return "Good";
  if (score >= 40) return "Fair";
  return "Critical";
}

function ScoreGauge({ score, size = 180 }: { score: number; size?: number }) {
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const center = size / 2;

  return (
    <div className="relative inline-flex items-center justify-center" data-testid="gauge-overall-score">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-muted/30"
        />
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          className={`${scoreStrokeColor(score)} transition-all duration-700`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-4xl font-bold tabular-nums ${scoreColor(score)}`} data-testid="value-overall-score">
          {score}
        </span>
        <span className="text-xs text-muted-foreground font-medium" data-testid="text-score-label">
          {scoreLabel(score)}
        </span>
      </div>
    </div>
  );
}

function ComponentScoreCard({
  title,
  score,
  icon: Icon,
  weight,
  loading,
}: {
  title: string;
  score: number;
  icon: typeof Cloud;
  weight: string;
  loading?: boolean;
}) {
  const testId = `card-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className="p-1.5 rounded-md bg-muted/50">
          <Icon className="h-3.5 w-3.5 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="space-y-1">
            <div className="flex items-baseline gap-2 flex-wrap">
              <span className={`text-2xl font-bold tabular-nums ${scoreColor(score)}`} data-testid={`value-${testId}`}>
                {score}
              </span>
              <span className="text-xs text-muted-foreground">/ 100</span>
            </div>
            <Badge
              variant="outline"
              className="no-default-hover-elevate no-default-active-elevate text-[10px]"
              data-testid={`badge-weight-${testId}`}
            >
              Weight: {weight}
            </Badge>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function PostureScoreTab() {
  const { toast } = useToast();

  const {
    data: latestScore,
    isPending: latestPending,
    isError: latestError,
    error: latestErrorObj,
    refetch: refetchLatest,
  } = useQuery<any>({
    queryKey: ["/api/posture/latest"],
  });

  const {
    data: scoreHistory,
    isPending: historyPending,
    isError: historyError,
    refetch: refetchHistory,
  } = useQuery<any[]>({
    queryKey: ["/api/posture/scores"],
  });

  const calculateMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/posture/calculate");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture/latest"] });
      queryClient.invalidateQueries({ queryKey: ["/api/posture/scores"] });
      toast({ title: "Score calculated", description: "Security posture score has been updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Calculation failed", description: err.message, variant: "destructive" });
    },
  });

  const isPending = latestPending || historyPending;
  const hasScore = latestScore && latestScore.overallScore != null;

  if (isPending) {
    return (
      <div className="space-y-6" data-testid="posture-score-loading">
        <div className="flex justify-center py-8">
          <Skeleton className="h-44 w-44 rounded-full" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (latestError || historyError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load security posture data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchLatest();
            refetchHistory();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="section-posture-score">
      {!hasScore ? (
        <Card data-testid="empty-posture-score">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Shield className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No posture score calculated yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Calculate your first security posture score to see your organization's security health
            </p>
            <Button
              className="mt-4"
              onClick={() => calculateMutation.mutate()}
              disabled={calculateMutation.isPending}
              data-testid="button-calculate-posture-empty"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${calculateMutation.isPending ? "animate-spin" : ""}`} />
              Calculate Score
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="flex justify-center py-4">
            <ScoreGauge score={latestScore.overallScore ?? 0} />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="component-scores">
            <ComponentScoreCard title="CSPM Score" score={latestScore.cspmScore ?? 0} icon={Cloud} weight="35%" />
            <ComponentScoreCard
              title="Endpoint Score"
              score={latestScore.endpointScore ?? 0}
              icon={Monitor}
              weight="30%"
            />
            <ComponentScoreCard
              title="Incident Score"
              score={latestScore.incidentScore ?? 0}
              icon={Shield}
              weight="20%"
            />
            <ComponentScoreCard
              title="Compliance Score"
              score={latestScore.complianceScore ?? 0}
              icon={FileCheck}
              weight="15%"
            />
          </div>

          {scoreHistory && scoreHistory.length > 0 && (
            <div data-testid="section-score-history">
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="h-5 w-5 text-muted-foreground" />
                <h2 className="text-lg font-semibold">Score History</h2>
                <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
                  {scoreHistory.length}
                </Badge>
              </div>
              <Card>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b">
                          <th className="text-left p-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Date
                          </th>
                          <th className="text-left p-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Overall
                          </th>
                          <th className="text-left p-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            CSPM
                          </th>
                          <th className="text-left p-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Endpoint
                          </th>
                          <th className="text-left p-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Incident
                          </th>
                          <th className="text-left p-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Compliance
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {ensureArray(scoreHistory)
                          .slice(0, 10)
                          .map((entry: any, idx: number) => (
                            <tr
                              key={entry.id || idx}
                              className="border-b last:border-b-0"
                              data-testid={`row-score-history-${idx}`}
                            >
                              <td
                                className="p-3 text-xs text-muted-foreground"
                                data-testid={`text-history-date-${idx}`}
                              >
                                {formatTimestamp(entry.generatedAt || entry.createdAt)}
                              </td>
                              <td className="p-3">
                                <span
                                  className={`font-bold tabular-nums ${scoreColor(entry.overallScore ?? 0)}`}
                                  data-testid={`value-history-overall-${idx}`}
                                >
                                  {entry.overallScore ?? 0}
                                </span>
                              </td>
                              <td className="p-3 text-xs tabular-nums" data-testid={`value-history-cspm-${idx}`}>
                                {entry.cspmScore ?? "—"}
                              </td>
                              <td className="p-3 text-xs tabular-nums" data-testid={`value-history-endpoint-${idx}`}>
                                {entry.endpointScore ?? "—"}
                              </td>
                              <td className="p-3 text-xs tabular-nums" data-testid={`value-history-incident-${idx}`}>
                                {entry.incidentScore ?? "—"}
                              </td>
                              <td className="p-3 text-xs tabular-nums" data-testid={`value-history-compliance-${idx}`}>
                                {entry.complianceScore ?? "—"}
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function AIDeploymentTab() {
  const { toast } = useToast();

  const { data: config, isPending } = useQuery<any>({
    queryKey: ["/api/ai-deployment/config"],
  });

  const [backend, setBackend] = useState("bedrock");
  const [modelId, setModelId] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [region, setRegion] = useState("");
  const [dataResidency, setDataResidency] = useState("us");
  const [allowExternalCalls, setAllowExternalCalls] = useState(false);

  useEffect(() => {
    if (config) {
      setBackend(config.backend || "bedrock");
      setModelId(config.modelId || "");
      setEndpointUrl(config.endpointUrl || "");
      setRegion(config.region || "");
      setDataResidency(config.dataResidency || "us");
      setAllowExternalCalls(config.allowExternalCalls ?? false);
    }
  }, [config]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("PUT", "/api/ai-deployment/config", {
        backend,
        modelId,
        endpointUrl,
        region,
        dataResidency,
        allowExternalCalls,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ai-deployment/config"] });
      toast({ title: "Configuration saved", description: "AI deployment settings have been updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Save failed", description: err.message, variant: "destructive" });
    },
  });

  if (isPending) {
    return (
      <div className="space-y-4" data-testid="ai-deployment-loading">
        <Card>
          <CardContent className="p-6 space-y-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-9 w-full" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="section-ai-deployment">
      <div>
        <h2 className="text-lg font-semibold" data-testid="text-ai-deployment-title">
          AI Deployment Configuration
        </h2>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-ai-deployment-description">
          Configure AI model backend, data residency, and on-prem deployment settings
        </p>
      </div>

      <Card>
        <CardContent className="p-6 space-y-5">
          <div className="space-y-2">
            <Label htmlFor="ai-backend" className="text-sm font-medium flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              Backend
            </Label>
            <Select value={backend} onValueChange={setBackend}>
              <SelectTrigger data-testid="select-ai-backend">
                <SelectValue placeholder="Select backend..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="bedrock">AWS Bedrock</SelectItem>
                <SelectItem value="sagemaker">AWS SageMaker</SelectItem>
                <SelectItem value="on_prem">On-Premises</SelectItem>
                <SelectItem value="azure_openai">Azure OpenAI</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="model-id" className="text-sm font-medium flex items-center gap-2">
              <Brain className="h-4 w-4 text-muted-foreground" />
              Model ID
            </Label>
            <Input
              id="model-id"
              value={modelId}
              onChange={(e) => setModelId(e.target.value)}
              placeholder="e.g. mistral.mistral-large-2402-v1:0"
              data-testid="input-model-id"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="endpoint-url" className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4 text-muted-foreground" />
              Endpoint URL
            </Label>
            <Input
              id="endpoint-url"
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
              placeholder="https://your-endpoint.example.com"
              data-testid="input-endpoint-url"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="region" className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4 text-muted-foreground" />
              Region
            </Label>
            <Input
              id="region"
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              placeholder="e.g. us-east-1"
              data-testid="input-region"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="data-residency" className="text-sm font-medium flex items-center gap-2">
              <LockUnlockIcon size={18} color="currentColor" />
              Data Residency
            </Label>
            <Select value={dataResidency} onValueChange={setDataResidency}>
              <SelectTrigger data-testid="select-data-residency">
                <SelectValue placeholder="Select data residency..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="us">United States (US)</SelectItem>
                <SelectItem value="eu">European Union (EU)</SelectItem>
                <SelectItem value="ap">Asia Pacific (AP)</SelectItem>
                <SelectItem value="sovereign">Sovereign Cloud</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium flex items-center gap-2">
                <Globe className="h-4 w-4 text-muted-foreground" />
                Allow External Calls
              </Label>
              <p className="text-xs text-muted-foreground">Allow the AI model to make calls to external services</p>
            </div>
            <Switch
              checked={allowExternalCalls}
              onCheckedChange={setAllowExternalCalls}
              data-testid="toggle-external-calls"
            />
          </div>

          <div className="pt-2">
            <Button
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending}
              data-testid="button-save-ai-config"
            >
              <Save className={`h-4 w-4 mr-2 ${saveMutation.isPending ? "animate-spin" : ""}`} />
              {saveMutation.isPending ? "Saving..." : "Save Configuration"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 27.1 Vulnerability Prioritization Matrix ───────────────────────────────

function VulnPrioritizationTab() {
  const { data, isLoading } = useQuery<any>({
    queryKey: ["/api/vulnerabilities/prioritized"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Card>
          <CardContent className="p-4">
            <Skeleton className="h-48 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data || !data.vulnerabilities) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <Target className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium text-muted-foreground">No vulnerability data available</p>
          <p className="text-xs text-muted-foreground mt-1">
            Add risks in the Risk Register to see prioritized vulnerabilities
          </p>
        </CardContent>
      </Card>
    );
  }

  const summary = data.summary || {};
  const vulns = data.vulnerabilities || [];

  return (
    <div className="space-y-4" data-testid="section-vuln-prioritization">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Total", value: summary.total ?? 0, icon: Bug, color: "" },
          {
            label: "Critical",
            value: summary.critical ?? 0,
            icon: AlertTriangle,
            color: summary.critical > 0 ? "text-red-500" : "",
          },
          { label: "High", value: summary.high ?? 0, icon: Shield, color: summary.high > 0 ? "text-orange-500" : "" },
          {
            label: "Medium",
            value: summary.medium ?? 0,
            icon: Activity,
            color: summary.medium > 0 ? "text-yellow-500" : "",
          },
          { label: "Avg Priority", value: summary.avgPriorityScore ?? 0, icon: Target, color: "" },
        ].map((item) => (
          <Card key={item.label}>
            <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                {item.label}
              </CardTitle>
              <div className="p-1.5 rounded-md bg-muted/50">
                <item.icon className="h-3.5 w-3.5 text-muted-foreground" />
              </div>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold tabular-nums ${item.color}`}>{item.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Target className="h-4 w-4" />
            Prioritized Remediation Queue
            <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] ml-auto">
              {vulns.length} items
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {vulns.slice(0, 20).map((v: any) => (
              <div key={v.id} className="p-3 rounded border bg-muted/20 space-y-2">
                <div className="flex items-start justify-between gap-2 flex-wrap">
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold">{v.title}</span>
                      <Badge variant={v.severity === "critical" ? "destructive" : "outline"} className="text-[10px]">
                        {v.severity}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${v.status === "closed" ? "text-green-500" : v.status === "open" ? "text-red-500" : "text-yellow-500"}`}
                      >
                        {v.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                      <span>
                        CVSS: <strong className="tabular-nums">{v.cvssScore}</strong>
                      </span>
                      <span>
                        EPSS: <strong className="tabular-nums">{(v.epssScore * 100).toFixed(0)}%</strong>
                      </span>
                      <span>
                        Asset: <strong>{v.assetCriticality}</strong>
                      </span>
                      <span>
                        Attack Path: <strong>{v.attackPathExposure}</strong>
                      </span>
                      {v.compensatingControls && <span className="text-green-500">Has compensating controls</span>}
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <span className="text-xs text-muted-foreground block">Priority</span>
                    <span
                      className={`text-xl font-bold tabular-nums ${v.priorityScore > 50 ? "text-red-500" : v.priorityScore > 25 ? "text-yellow-500" : "text-green-500"}`}
                    >
                      {v.priorityScore}
                    </span>
                  </div>
                </div>
                {v.owner && <p className="text-xs text-muted-foreground">Owner: {v.owner}</p>}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 27.2 Vulnerability Aging Report ─────────────────────────────────────────

function VulnAgingTab() {
  const { data, isLoading } = useQuery<any>({
    queryKey: ["/api/vulnerabilities/aging"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Card>
          <CardContent className="p-4">
            <Skeleton className="h-48 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <Clock className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium text-muted-foreground">No aging data available</p>
        </CardContent>
      </Card>
    );
  }

  const sla = data.slaCompliance || {};
  const histogram = data.histogram || {};
  const report = data.agingReport || [];
  const histogramEntries = Object.entries(histogram) as [string, number][];
  const maxHistValue = Math.max(1, ...histogramEntries.map(([, v]) => v));

  return (
    <div className="space-y-4" data-testid="section-vuln-aging">
      {/* SLA Compliance summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              SLA Compliance
            </CardTitle>
            <div className="p-1.5 rounded-md bg-muted/50">
              <CheckCircle className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <div
              className={`text-2xl font-bold tabular-nums ${sla.complianceRate === null || sla.complianceRate === undefined ? "text-muted-foreground" : sla.complianceRate >= 80 ? "text-green-500" : sla.complianceRate >= 60 ? "text-yellow-500" : "text-red-500"}`}
            >
              {sla.complianceRate === null || sla.complianceRate === undefined
                ? "Unavailable"
                : `${sla.complianceRate}%`}
            </div>
            {sla.complianceRate !== null && sla.complianceRate !== undefined && (
              <Progress value={sla.complianceRate} className="h-2 mt-2" />
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total</CardTitle>
            <div className="p-1.5 rounded-md bg-muted/50">
              <Bug className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tabular-nums">{sla.total ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Compliant
            </CardTitle>
            <div className="p-1.5 rounded-md bg-muted/50">
              <CheckCircle className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tabular-nums text-green-500">{sla.compliant ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              SLA Breached
            </CardTitle>
            <div className="p-1.5 rounded-md bg-muted/50">
              <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold tabular-nums ${(sla.breached ?? 0) > 0 ? "text-red-500" : ""}`}>
              {sla.breached ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* SLA Reference */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Clock className="h-4 w-4" />
            SLA Targets
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            {[
              { severity: "Critical", days: 7, color: "text-red-500" },
              { severity: "High", days: 14, color: "text-orange-500" },
              { severity: "Medium", days: 30, color: "text-yellow-500" },
              { severity: "Low", days: 90, color: "text-green-500" },
            ].map((slaTarget) => (
              <div key={slaTarget.severity} className="p-2 rounded bg-muted/30 text-center">
                <span className={`font-bold ${slaTarget.color}`}>{slaTarget.severity}</span>
                <p className="text-xs text-muted-foreground mt-0.5">{slaTarget.days} days</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Aging Histogram */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <BarChart3 className="h-4 w-4" />
            Aging Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {histogramEntries.map(([bucket, count]) => (
              <div key={bucket} className="flex items-center gap-3">
                <span className="text-xs font-medium w-24 flex-shrink-0">{bucket}</span>
                <div className="flex-1 bg-muted/30 rounded-full h-4">
                  <div
                    className={`h-4 rounded-full transition-all ${bucket.includes("90+") ? "bg-red-500" : bucket.includes("61") ? "bg-orange-500" : bucket.includes("31") ? "bg-yellow-500" : "bg-blue-500"}`}
                    style={{ width: `${(count / maxHistValue) * 100}%` }}
                  />
                </div>
                <span className="text-xs tabular-nums font-bold w-8 text-right">{count}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Breached items */}
      {report.filter((r: any) => r.slaBreached && r.status !== "closed").length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              SLA Breached Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {report
                .filter((r: any) => r.slaBreached && r.status !== "closed")
                .slice(0, 10)
                .map((r: any) => (
                  <div
                    key={r.id}
                    className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-red-500/5 border border-red-500/10"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <XCircle className="h-4 w-4 text-red-500 flex-shrink-0" />
                      <span className="font-medium truncate">{r.title}</span>
                      <Badge variant="destructive" className="text-[10px]">
                        {r.severity}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 text-xs text-muted-foreground">
                      <span className="tabular-nums font-bold text-red-500">{r.ageDays}d old</span>
                      <span>(SLA: {r.slaDays}d)</span>
                    </div>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── 27.3 Remediation Workflow Tracking ──────────────────────────────────────

function RemediationWorkflowTab() {
  const { data, isLoading } = useQuery<any>({
    queryKey: ["/api/vulnerabilities/remediation-tracking"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <Wrench className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium text-muted-foreground">No remediation data available</p>
        </CardContent>
      </Card>
    );
  }

  const summary = data.summary || {};
  const tracking = data.tracking || [];

  const stages = [
    {
      key: "identified",
      label: "Identified",
      icon: Search,
      color: "text-blue-500",
      bgColor: "bg-blue-500/10 border-blue-500/20",
    },
    {
      key: "assigned",
      label: "Assigned",
      icon: Users,
      color: "text-purple-500",
      bgColor: "bg-purple-500/10 border-purple-500/20",
    },
    {
      key: "inProgress",
      label: "In Progress",
      icon: Wrench,
      color: "text-yellow-500",
      bgColor: "bg-yellow-500/10 border-yellow-500/20",
    },
    {
      key: "verified",
      label: "Verified",
      icon: CheckCircle,
      color: "text-green-500",
      bgColor: "bg-green-500/10 border-green-500/20",
    },
  ];

  return (
    <div className="space-y-4" data-testid="section-remediation-workflow">
      {/* Workflow summary counters */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {stages.map((stage) => (
          <Card key={stage.key}>
            <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                {stage.label}
              </CardTitle>
              <div className="p-1.5 rounded-md bg-muted/50">
                <stage.icon className={`h-3.5 w-3.5 ${stage.color}`} />
              </div>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold tabular-nums ${stage.color}`}>{summary[stage.key] ?? 0}</div>
            </CardContent>
          </Card>
        ))}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Overdue
            </CardTitle>
            <div className="p-1.5 rounded-md bg-muted/50">
              <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
            </div>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold tabular-nums ${(summary.overdue ?? 0) > 0 ? "text-red-500" : ""}`}>
              {summary.overdue ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Workflow pipeline visualization */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Remediation Pipeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between gap-2 mb-6 flex-wrap">
            {stages.map((stage, idx) => (
              <div key={stage.key} className="flex items-center gap-2 flex-1 min-w-[120px]">
                <div className={`flex-1 p-3 rounded border text-center ${stage.bgColor}`}>
                  <stage.icon className={`h-5 w-5 mx-auto mb-1 ${stage.color}`} />
                  <p className="text-xs font-medium">{stage.label}</p>
                  <p className={`text-lg font-bold tabular-nums ${stage.color}`}>{summary[stage.key] ?? 0}</p>
                </div>
                {idx < stages.length - 1 && <span className="text-muted-foreground text-lg">→</span>}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Item list by stage */}
      {stages.map((stage) => {
        const items = tracking.filter(
          (t: any) => t.workflowStatus === stage.key.replace(/([A-Z])/g, "_$1").toLowerCase(),
        );
        if (items.length === 0) return null;
        return (
          <Card key={stage.key}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <stage.icon className={`h-4 w-4 ${stage.color}`} />
                {stage.label}
                <Badge
                  variant="outline"
                  className="no-default-hover-elevate no-default-active-elevate text-[10px] ml-auto"
                >
                  {items.length}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {items.slice(0, 10).map((item: any) => (
                  <div
                    key={item.id}
                    className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-medium truncate">{item.title}</span>
                      <Badge variant={item.severity === "critical" ? "destructive" : "outline"} className="text-[10px]">
                        {item.severity}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0 text-xs">
                      <span className="text-muted-foreground">{item.assignee}</span>
                      {item.isOverdue && (
                        <Badge variant="destructive" className="text-[10px]">
                          OVERDUE
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ─── 27.4 + 27.5 + 27.6 + 27.7 + 27.8 Trends & Scanner & Correlation ──────

function VulnTrendsAndToolsTab() {
  const { data: trends, isLoading: trendsLoading } = useQuery<any>({
    queryKey: ["/api/vulnerabilities/trends"],
  });

  const { data: scanners } = useQuery<any>({
    queryKey: ["/api/vulnerabilities/scanners"],
  });

  const { data: cspmCorrelation } = useQuery<any>({
    queryKey: ["/api/vulnerabilities/cspm-correlation"],
  });

  if (trendsLoading) {
    return (
      <div className="space-y-4">
        <Card>
          <CardContent className="p-4">
            <Skeleton className="h-48 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-vuln-trends-tools">
      {/* 27.4 Trend Summary */}
      {trends && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Remediation Rate
                </CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50">
                  <TrendingUp className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <div
                  className={`text-2xl font-bold tabular-nums ${(trends.remediationRate ?? 0) >= 70 ? "text-green-500" : "text-yellow-500"}`}
                >
                  {trends.remediationRate ?? 0}%
                </div>
                <Progress value={trends.remediationRate ?? 0} className="h-2 mt-2" />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Vuln Debt
                </CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50">
                  <Bug className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <div
                  className={`text-2xl font-bold tabular-nums ${(trends.vulnerabilityDebt ?? 0) > 10 ? "text-red-500" : ""}`}
                >
                  {trends.vulnerabilityDebt ?? 0}
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">open vulns</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Created
                </CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50">
                  <Bug className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold tabular-nums">{trends.totalCreated ?? 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Closed
                </CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50">
                  <CheckCircle className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold tabular-nums text-green-500">{trends.totalClosed ?? 0}</div>
              </CardContent>
            </Card>
          </div>

          {/* MTTR by Severity */}
          {trends.mttr && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Mean Time to Remediate (MTTR) by Severity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  {[
                    { severity: "Critical", days: trends.mttr.critical ?? 0, color: "text-red-500" },
                    { severity: "High", days: trends.mttr.high ?? 0, color: "text-orange-500" },
                    { severity: "Medium", days: trends.mttr.medium ?? 0, color: "text-yellow-500" },
                    { severity: "Low", days: trends.mttr.low ?? 0, color: "text-green-500" },
                  ].map((item) => (
                    <div key={item.severity} className="p-3 rounded border bg-muted/20">
                      <span className={`text-xs font-medium ${item.color}`}>{item.severity}</span>
                      <p className={`text-2xl font-bold tabular-nums mt-1 ${item.color}`}>{item.days}d</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Weekly Trends */}
          {(trends.weeklyTrends || []).length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  Weekly Vulnerability Trends
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Week
                        </th>
                        <th className="text-right p-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          New
                        </th>
                        <th className="text-right p-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Closed
                        </th>
                        <th className="text-right p-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Open
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {(trends.weeklyTrends || []).slice(-8).map((w: any, idx: number) => (
                        <tr key={idx} className="border-b last:border-b-0">
                          <td className="p-2 text-xs text-muted-foreground">{w.weekStart}</td>
                          <td className="p-2 text-right tabular-nums text-red-500 font-medium">{w.newVulns}</td>
                          <td className="p-2 text-right tabular-nums text-green-500 font-medium">{w.closedVulns}</td>
                          <td className="p-2 text-right tabular-nums font-bold">{w.openVulns}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* 27.5 Available Scanners */}
      {scanners && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Search className="h-4 w-4" />
              Available Vulnerability Scanners
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(scanners.available || []).map((scanner: any) => (
                <div key={scanner.id} className="p-3 rounded border bg-muted/20 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-sm">{scanner.name}</span>
                    <Badge variant={scanner.status === "active" ? "default" : "outline"} className="text-[10px]">
                      {scanner.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{scanner.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {(scanner.capabilities || []).map((cap: string) => (
                      <Badge key={cap} variant="secondary" className="text-[9px]">
                        {cap.replace(/_/g, " ")}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 27.8 CSPM Correlation Summary */}
      {cspmCorrelation && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Network className="h-4 w-4" />
              Cloud + Infrastructure Unified View
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
              <div className="p-2 rounded bg-muted/30">
                <span className="text-xs text-muted-foreground">Infra Vulns</span>
                <p className="text-lg font-bold tabular-nums">{cspmCorrelation.totalInfrastructureVulns ?? 0}</p>
              </div>
              <div className="p-2 rounded bg-muted/30">
                <span className="text-xs text-muted-foreground">Cloud Findings</span>
                <p className="text-lg font-bold tabular-nums">{cspmCorrelation.totalCloudFindings ?? 0}</p>
              </div>
              <div className="p-2 rounded bg-muted/30">
                <span className="text-xs text-muted-foreground">Correlated</span>
                <p className="text-lg font-bold tabular-nums text-blue-500">{cspmCorrelation.correlatedItems ?? 0}</p>
              </div>
              <div className="p-2 rounded bg-muted/30">
                <span className="text-xs text-muted-foreground">Cloud-Only</span>
                <p className="text-lg font-bold tabular-nums">{cspmCorrelation.cloudOnlyItems ?? 0}</p>
              </div>
            </div>

            {cspmCorrelation.summary && (
              <div className="flex items-center gap-3 flex-wrap text-xs">
                <span className="text-red-500 font-bold">Critical: {cspmCorrelation.summary.critical ?? 0}</span>
                <span className="text-orange-500 font-bold">High: {cspmCorrelation.summary.high ?? 0}</span>
                <span className="text-yellow-500 font-bold">Medium: {cspmCorrelation.summary.medium ?? 0}</span>
                <span className="text-green-500 font-bold">Low: {cspmCorrelation.summary.low ?? 0}</span>
              </div>
            )}

            {(cspmCorrelation.unified || []).length > 0 && (
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {(cspmCorrelation.unified || []).slice(0, 10).map((item: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/20">
                    <div className="flex items-center gap-2 min-w-0">
                      <Badge
                        variant="outline"
                        className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${item.source === "both" ? "text-blue-500" : item.source === "cloud" ? "text-purple-500" : "text-orange-500"}`}
                      >
                        {item.source}
                      </Badge>
                      <span className="truncate text-xs">{item.riskTitle}</span>
                    </div>
                    <Badge
                      variant={item.unifiedSeverity === "critical" ? "destructive" : "outline"}
                      className="text-[10px]"
                    >
                      {item.unifiedSeverity}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function SecurityPosturePage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("posture-score");

  const calculateMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/posture/calculate");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/posture/latest"] });
      queryClient.invalidateQueries({ queryKey: ["/api/posture/scores"] });
      toast({ title: "Score calculated", description: "Security posture score has been updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Calculation failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-security-posture">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Security Posture</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Unified security posture scoring across cloud, endpoint, and incident domains
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        {activeTab === "posture-score" && (
          <Button
            onClick={() => calculateMutation.mutate()}
            disabled={calculateMutation.isPending}
            data-testid="button-calculate-posture"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${calculateMutation.isPending ? "animate-spin" : ""}`} />
            {calculateMutation.isPending ? "Calculating..." : "Calculate Score"}
          </Button>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList data-testid="tabs-security-posture">
          <TabsTrigger value="posture-score" data-testid="tab-posture-score">
            <Shield className="h-4 w-4 mr-1.5" />
            Posture Score
          </TabsTrigger>
          <TabsTrigger value="prioritization" data-testid="tab-prioritization">
            <Target className="h-4 w-4 mr-1.5" />
            Prioritization
          </TabsTrigger>
          <TabsTrigger value="aging" data-testid="tab-aging">
            <Clock className="h-4 w-4 mr-1.5" />
            Aging
          </TabsTrigger>
          <TabsTrigger value="remediation" data-testid="tab-remediation">
            <Wrench className="h-4 w-4 mr-1.5" />
            Remediation
          </TabsTrigger>
          <TabsTrigger value="trends-tools" data-testid="tab-trends-tools">
            <BarChart3 className="h-4 w-4 mr-1.5" />
            Trends & Tools
          </TabsTrigger>
          <TabsTrigger value="ai-deployment" data-testid="tab-ai-deployment">
            <Brain className="h-4 w-4 mr-1.5" />
            AI Deployment
          </TabsTrigger>
        </TabsList>

        <TabsContent value="posture-score" className="mt-4">
          <PostureScoreTab />
        </TabsContent>

        <TabsContent value="prioritization" className="mt-4">
          <VulnPrioritizationTab />
        </TabsContent>

        <TabsContent value="aging" className="mt-4">
          <VulnAgingTab />
        </TabsContent>

        <TabsContent value="remediation" className="mt-4">
          <RemediationWorkflowTab />
        </TabsContent>

        <TabsContent value="trends-tools" className="mt-4">
          <VulnTrendsAndToolsTab />
        </TabsContent>

        <TabsContent value="ai-deployment" className="mt-4">
          <AIDeploymentTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
