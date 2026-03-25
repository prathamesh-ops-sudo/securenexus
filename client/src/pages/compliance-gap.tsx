import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  ClipboardCheck,
  Play,
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Shield,
  Target,
  Loader2,
  RefreshCw,
  TrendingUp,
  Minus,
  ChevronDown,
  ChevronRight,
  Wrench,
  Zap,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function ComplianceGapPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedAnalysis, setSelectedAnalysis] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  const { data: frameworks } = useQuery({
    queryKey: ["/api/compliance-gap/frameworks"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/compliance-gap/frameworks");
      return r.json();
    },
  });

  const { data: analyses, isLoading } = useQuery({
    queryKey: ["/api/compliance-gap/analyses"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/compliance-gap/analyses");
      return r.json();
    },
  });

  const { data: detail } = useQuery({
    queryKey: ["/api/compliance-gap/analyses", selectedAnalysis],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/compliance-gap/analyses/${selectedAnalysis}`);
      return r.json();
    },
    enabled: !!selectedAnalysis,
  });

  const analyzeMutation = useMutation({
    mutationFn: async (framework: string) => {
      const r = await apiRequest("POST", "/api/compliance-gap/analyze", { framework });
      return r.json();
    },
    onSuccess: (data: any) => {
      toast({ title: "Analysis Complete", description: `Compliance score: ${data?.complianceScore || 0}%` });
      queryClient.invalidateQueries({ queryKey: ["/api/compliance-gap/analyses"] });
      if (data?.id) setSelectedAnalysis(data.id);
    },
    onError: () => toast({ title: "Analysis Failed", variant: "destructive" }),
  });

  const frameworkList = Array.isArray(frameworks) ? frameworks : [];
  const analysisList = Array.isArray(analyses) ? analyses : (analyses as any)?.data || [];
  const analysisDetail = detail as any;

  const toggleCategory = (cat: string) => {
    const next = new Set(expandedCategories);
    if (next.has(cat)) next.delete(cat);
    else next.add(cat);
    setExpandedCategories(next);
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ClipboardCheck className="h-6 w-6 text-amber-400" />
            Compliance Gap Analysis
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Automated compliance assessment against industry frameworks
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {frameworkList.map((fw: any) => (
          <Card key={fw.id} className="border-amber-500/20 bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">{fw.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-muted-foreground">
                  v{fw.version} | {fw.controlCount} controls
                </span>
              </div>
              <Button
                size="sm"
                onClick={() => analyzeMutation.mutate(fw.id)}
                disabled={analyzeMutation.isPending}
                className="w-full bg-amber-600 hover:bg-amber-700"
              >
                {analyzeMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Play className="h-4 w-4 mr-2" />
                )}
                Run Analysis
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {analysisList.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Analysis History</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {analysisList.map((a: any) => (
              <Card
                key={a.id}
                onClick={() => setSelectedAnalysis(a.id)}
                className={`cursor-pointer transition-all hover:border-amber-500/30 ${selectedAnalysis === a.id ? "border-amber-400 bg-amber-500/5" : "border-border bg-card/50"}`}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">{a.framework}</span>
                    <ScoreBadge score={a.complianceScore} />
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3 text-green-500" /> {a.implementedControls}
                    </span>
                    <span className="flex items-center gap-1">
                      <XCircle className="h-3 w-3 text-red-400" /> {a.missingControls}
                    </span>
                    <span>{a.totalControls} total</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">{new Date(a.createdAt).toLocaleDateString()}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {analysisList.length === 0 && (
        <Card className="border-dashed border-border bg-card/30">
          <CardContent className="py-12 text-center">
            <ClipboardCheck className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">Run your first compliance gap analysis above</p>
          </CardContent>
        </Card>
      )}

      {selectedAnalysis && analysisDetail && (
        <div className="space-y-4">
          <Card className="border-amber-500/20 bg-card/50">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">
                  {analysisDetail.framework} v{analysisDetail.version}
                </CardTitle>
                <div className="flex items-center gap-3">
                  <ComplianceGauge score={analysisDetail.complianceScore} />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4 text-center">
                <div>
                  <div className="text-2xl font-bold text-green-400">{analysisDetail.implementedControls}</div>
                  <div className="text-xs text-muted-foreground">Implemented</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-yellow-400">{analysisDetail.partialControls}</div>
                  <div className="text-xs text-muted-foreground">Partial</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-red-400">{analysisDetail.missingControls}</div>
                  <div className="text-xs text-muted-foreground">Missing</div>
                </div>
                <div>
                  <div className="text-2xl font-bold">{analysisDetail.totalControls}</div>
                  <div className="text-xs text-muted-foreground">Total</div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-amber-500/20 bg-card/50">
            <CardHeader>
              <CardTitle className="text-sm">Control Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              {Object.entries(
                (analysisDetail.gaps || []).reduce((acc: Record<string, any[]>, gap: any) => {
                  if (!acc[gap.category]) acc[gap.category] = [];
                  acc[gap.category].push(gap);
                  return acc;
                }, {}),
              ).map(([category, rawGaps]: [string, unknown]) => {
                const gaps = rawGaps as any[];
                return (
                  <div key={category} className="mb-4">
                    <button
                      onClick={() => toggleCategory(category)}
                      className="flex items-center gap-2 w-full text-left p-2 hover:bg-background/50 rounded"
                    >
                      {expandedCategories.has(category) ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                      <span className="text-sm font-semibold">{category}</span>
                      <span className="text-xs text-muted-foreground">({gaps.length} controls)</span>
                      <span className="ml-auto text-xs">
                        <span className="text-green-400">
                          {gaps.filter((g: any) => g.status === "implemented").length}
                        </span>
                        {" / "}
                        <span className="text-yellow-400">
                          {gaps.filter((g: any) => g.status === "partial").length}
                        </span>
                        {" / "}
                        <span className="text-red-400">{gaps.filter((g: any) => g.status === "missing").length}</span>
                      </span>
                    </button>
                    {expandedCategories.has(category) && (
                      <div className="pl-6 space-y-2 mt-2">
                        {gaps.map((gap: any) => (
                          <div
                            key={gap.controlId}
                            className="flex items-center justify-between p-2 rounded bg-background/50 border border-border"
                          >
                            <div className="flex items-center gap-2">
                              <ControlStatusIcon status={gap.status} />
                              <div>
                                <div className="text-sm font-medium">
                                  {gap.controlId} - {gap.controlName}
                                </div>
                                <div className="text-xs text-muted-foreground">{gap.description}</div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <PriorityBadge priority={gap.remediationPriority} />
                              <span className="text-xs text-muted-foreground">{gap.estimatedEffort}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </CardContent>
          </Card>

          {analysisDetail.recommendations?.length > 0 && (
            <Card className="border-amber-500/20 bg-card/50">
              <CardHeader>
                <CardTitle className="text-sm">Recommendations</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {analysisDetail.recommendations.map((rec: any) => (
                    <div
                      key={rec.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-background/50 border border-border"
                    >
                      <div className="flex items-center gap-3">
                        <Wrench className="h-4 w-4 text-amber-400" />
                        <div>
                          <div className="text-sm font-medium">{rec.title}</div>
                          <div className="text-xs text-muted-foreground">{rec.description}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <PriorityBadge priority={rec.priority} />
                        <span className="text-xs text-muted-foreground">{rec.estimatedEffort}</span>
                        {rec.automatable && (
                          <Badge className="text-xs bg-cyan-500/20 text-cyan-400">
                            <Zap className="h-3 w-3 mr-1" />
                            Auto
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const color = score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400";
  return <span className={`text-lg font-bold ${color}`}>{score}%</span>;
}

function ComplianceGauge({ score }: { score: number }) {
  const color = score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400";
  const bg = score >= 80 ? "bg-green-400" : score >= 60 ? "bg-yellow-400" : "bg-red-400";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${bg} rounded-full transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-lg font-bold ${color}`}>{score}%</span>
    </div>
  );
}

function ControlStatusIcon({ status }: { status: string }) {
  switch (status) {
    case "implemented":
      return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    case "partial":
      return <Minus className="h-4 w-4 text-yellow-400" />;
    case "missing":
      return <XCircle className="h-4 w-4 text-red-400" />;
    default:
      return <Shield className="h-4 w-4 text-muted-foreground" />;
  }
}

function PriorityBadge({ priority }: { priority: string }) {
  const styles: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-yellow-500/20 text-yellow-400",
    low: "bg-green-500/20 text-green-400",
  };
  return <Badge className={`text-xs ${styles[priority] || styles.medium}`}>{priority}</Badge>;
}
