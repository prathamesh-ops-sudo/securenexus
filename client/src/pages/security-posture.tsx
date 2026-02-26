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
import { apiRequest, queryClient } from "@/lib/queryClient";
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
} from "lucide-react";

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

function _scoreBgColor(score: number): string {
  if (score >= 80) return "bg-green-500/10 border-green-500/30";
  if (score >= 60) return "bg-yellow-500/10 border-yellow-500/30";
  if (score >= 40) return "bg-orange-500/10 border-orange-500/30";
  return "bg-red-500/10 border-red-500/30";
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Excellent";
  if (score >= 60) return "Good";
  if (score >= 40) return "Fair";
  return "Critical";
}

function formatTimestamp(date: string | Date | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
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
    isLoading: latestLoading,
    isError: latestError,
    refetch: refetchLatest,
  } = useQuery<any>({
    queryKey: ["/api/posture/latest"],
  });

  const {
    data: scoreHistory,
    isLoading: historyLoading,
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

  const isLoading = latestLoading || historyLoading;
  const hasScore = latestScore && latestScore.overallScore != null;

  if (isLoading) {
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
                        {scoreHistory.slice(0, 10).map((entry: any, idx: number) => (
                          <tr
                            key={entry.id || idx}
                            className="border-b last:border-b-0"
                            data-testid={`row-score-history-${idx}`}
                          >
                            <td className="p-3 text-xs text-muted-foreground" data-testid={`text-history-date-${idx}`}>
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

  const { data: config, isLoading } = useQuery<any>({
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

  if (isLoading) {
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
              <Lock className="h-4 w-4 text-muted-foreground" />
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
          <TabsTrigger value="ai-deployment" data-testid="tab-ai-deployment">
            <Brain className="h-4 w-4 mr-1.5" />
            AI Deployment
          </TabsTrigger>
        </TabsList>

        <TabsContent value="posture-score" className="mt-4">
          <PostureScoreTab />
        </TabsContent>

        <TabsContent value="ai-deployment" className="mt-4">
          <AIDeploymentTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
