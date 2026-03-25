import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  BarChart3,
  FileText,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Target,
  Clock,
  Users,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface ComplianceControl {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  description: string;
  status: "met" | "partial" | "not_met" | "not_applicable";
  evidence: string[];
  remediation: string;
  /* 80.2 — gap remediation tracking */
  assignedTo?: string | null;
  remediationDueDate?: string | null;
  remediationProgress?: number;
  /* 80.4 — automated gap detection */
  detectedAt?: string | null;
  detectionSource?: string;
  /* 80.5 — gap prioritization */
  priority?: "critical" | "high" | "medium" | "low";
  riskScore?: number;
}

interface Framework {
  id: string;
  name: string;
  version: string;
  controlCount: number;
  metCount: number;
  partialCount: number;
  notMetCount: number;
  /* 80.3 — gap trend over time */
  previousScore?: number;
  trendDirection?: "improving" | "declining" | "stable";
}

export default function GapAnalysisPage() {
  usePageTitle("Compliance Gap Analysis");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedFramework, setSelectedFramework] = useState("all");

  const {
    data: controls,
    isLoading,
    isError,
    refetch,
  } = useQuery<ComplianceControl[]>({
    queryKey: ["/api/compliance-controls"],
    queryFn: () => apiRequest("GET", "/api/compliance-controls").then((r) => r.json()),
  });

  const list = Array.isArray(controls) ? controls : [];

  const frameworks: Framework[] = (() => {
    const map = new Map<string, Framework>();
    for (const c of list) {
      const fw = map.get(c.frameworkId) || {
        id: c.frameworkId,
        name: c.frameworkId,
        version: "1.0",
        controlCount: 0,
        metCount: 0,
        partialCount: 0,
        notMetCount: 0,
      };
      fw.controlCount++;
      if (c.status === "met") fw.metCount++;
      else if (c.status === "partial") fw.partialCount++;
      else if (c.status === "not_met") fw.notMetCount++;
      map.set(c.frameworkId, fw);
    }
    return Array.from(map.values());
  })();

  const filtered = list.filter((c) => {
    if (
      search &&
      !c.title.toLowerCase().includes(search.toLowerCase()) &&
      !c.controlId.toLowerCase().includes(search.toLowerCase())
    )
      return false;
    if (statusFilter !== "all" && c.status !== statusFilter) return false;
    if (selectedFramework !== "all" && c.frameworkId !== selectedFramework) return false;
    return true;
  });

  const totalMet = list.filter((c) => c.status === "met").length;
  const totalPartial = list.filter((c) => c.status === "partial").length;
  const totalNotMet = list.filter((c) => c.status === "not_met").length;
  const overallScore = list.length > 0 ? Math.round(((totalMet + totalPartial * 0.5) / list.length) * 100) : 0;

  const statusIcon = (s: string) => {
    if (s === "met") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "partial") return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    if (s === "not_met") return <XCircle className="h-4 w-4 text-red-500" />;
    return <FileText className="h-4 w-4 text-muted-foreground" />;
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
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load compliance controls</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" /> Compliance Gap Analysis
          </h1>
          <p className="text-muted-foreground text-sm mt-1">Identify and track compliance gaps across frameworks</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-primary" />
              <div>
                <p className="text-2xl font-bold">{overallScore}%</p>
                <p className="text-xs text-muted-foreground">Overall Score</p>
              </div>
            </div>
            <Progress value={overallScore} className="mt-2" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{totalMet}</p>
                <p className="text-xs text-muted-foreground">Controls Met</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-2xl font-bold">{totalPartial}</p>
                <p className="text-xs text-muted-foreground">Partially Met</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-2xl font-bold">{totalNotMet}</p>
                <p className="text-xs text-muted-foreground">Not Met</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="controls">
        <TabsList>
          <TabsTrigger value="controls">Controls</TabsTrigger>
          <TabsTrigger value="frameworks">By Framework</TabsTrigger>
          {/* 80.1 — gap visualization matrix tab */}
          <TabsTrigger value="matrix">Gap Matrix</TabsTrigger>
          {/* 80.2 — remediation tracking tab */}
          <TabsTrigger value="remediation">Remediation</TabsTrigger>
        </TabsList>

        <TabsContent value="controls" className="space-y-4">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search controls..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="met">Met</SelectItem>
                <SelectItem value="partial">Partial</SelectItem>
                <SelectItem value="not_met">Not Met</SelectItem>
                <SelectItem value="not_applicable">N/A</SelectItem>
              </SelectContent>
            </Select>
            <Select value={selectedFramework} onValueChange={setSelectedFramework}>
              <SelectTrigger className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Frameworks</SelectItem>
                {frameworks.map((f) => (
                  <SelectItem key={f.id} value={f.id}>
                    {f.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {filtered.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Shield className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No controls found</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {filtered.map((c) => (
                <Card key={c.id} className="transition-all hover:shadow-sm">
                  <CardContent className="py-3 flex items-center gap-4">
                    {statusIcon(c.status)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-muted-foreground">{c.controlId}</span>
                        <span className="font-medium text-sm truncate">{c.title}</span>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">{c.description}</p>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {c.frameworkId}
                    </Badge>
                    <Badge
                      variant={c.status === "met" ? "default" : c.status === "not_met" ? "destructive" : "secondary"}
                    >
                      {c.status.replace("_", " ")}
                    </Badge>
                    {c.remediation && (
                      <Button variant="ghost" size="sm" className="text-xs">
                        Fix <ArrowRight className="ml-1 h-3 w-3" />
                      </Button>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="frameworks" className="space-y-4">
          {frameworks.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Shield className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No frameworks found</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {frameworks.map((f) => {
                const score =
                  f.controlCount > 0 ? Math.round(((f.metCount + f.partialCount * 0.5) / f.controlCount) * 100) : 0;
                return (
                  <Card key={f.id}>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base flex items-center gap-2">
                        {f.name}
                        {/* 80.3 — trend indicator */}
                        {f.trendDirection === "improving" && <TrendingUp className="h-4 w-4 text-green-500" />}
                        {f.trendDirection === "declining" && <TrendingDown className="h-4 w-4 text-red-500" />}
                      </CardTitle>
                      <CardDescription>
                        {f.controlCount} controls &middot; v{f.version}
                        {f.previousScore !== undefined && <span className="ml-2">(prev: {f.previousScore}%)</span>}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-2xl font-bold">{score}%</span>
                        <div className="flex gap-3 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <CheckCircle2 className="h-3 w-3 text-green-500" /> {f.metCount}
                          </span>
                          <span className="flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3 text-yellow-500" /> {f.partialCount}
                          </span>
                          <span className="flex items-center gap-1">
                            <XCircle className="h-3 w-3 text-red-500" /> {f.notMetCount}
                          </span>
                        </div>
                      </div>
                      <Progress value={score} />
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* 80.1 — Gap Visualization Matrix */}
        <TabsContent value="matrix" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="h-5 w-5" /> Gap Visualization Matrix
              </CardTitle>
              <CardDescription>Control vs. compliance status across all frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              {frameworks.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No framework data available</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Framework</th>
                        <th className="text-center py-2 px-3 text-xs font-medium text-green-500">Met</th>
                        <th className="text-center py-2 px-3 text-xs font-medium text-yellow-500">Partial</th>
                        <th className="text-center py-2 px-3 text-xs font-medium text-red-500">Not Met</th>
                        <th className="text-center py-2 px-3 text-xs font-medium text-muted-foreground">Score</th>
                        <th className="text-center py-2 px-3 text-xs font-medium text-muted-foreground">Coverage</th>
                      </tr>
                    </thead>
                    <tbody>
                      {frameworks.map((f) => {
                        const score =
                          f.controlCount > 0
                            ? Math.round(((f.metCount + f.partialCount * 0.5) / f.controlCount) * 100)
                            : 0;
                        return (
                          <tr key={f.id} className="border-b border-border/30">
                            <td className="py-2 px-3 font-medium">{f.name}</td>
                            <td className="text-center py-2 px-3">
                              <span className="inline-block w-8 h-6 leading-6 rounded bg-green-500/15 text-green-500 text-xs font-medium">
                                {f.metCount}
                              </span>
                            </td>
                            <td className="text-center py-2 px-3">
                              <span className="inline-block w-8 h-6 leading-6 rounded bg-yellow-500/15 text-yellow-500 text-xs font-medium">
                                {f.partialCount}
                              </span>
                            </td>
                            <td className="text-center py-2 px-3">
                              <span className="inline-block w-8 h-6 leading-6 rounded bg-red-500/15 text-red-500 text-xs font-medium">
                                {f.notMetCount}
                              </span>
                            </td>
                            <td className="text-center py-2 px-3 font-bold">{score}%</td>
                            <td className="py-2 px-3">
                              <Progress value={score} className="h-2" />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 80.2 — Remediation Tracking */}
        <TabsContent value="remediation" className="space-y-4">
          {(() => {
            const gaps = list.filter((c) => c.status === "not_met" || c.status === "partial");
            const withAssignment = gaps.filter((g) => g.assignedTo);
            const withDueDate = gaps.filter((g) => g.remediationDueDate);
            return (
              <>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <Card>
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-2">
                        <Target className="h-5 w-5 text-red-500" />
                        <div>
                          <p className="text-2xl font-bold">{gaps.length}</p>
                          <p className="text-xs text-muted-foreground">Open Gaps</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-2">
                        <Users className="h-5 w-5 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{withAssignment.length}</p>
                          <p className="text-xs text-muted-foreground">Assigned</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-2">
                        <Clock className="h-5 w-5 text-amber-500" />
                        <div>
                          <p className="text-2xl font-bold">{withDueDate.length}</p>
                          <p className="text-xs text-muted-foreground">With Due Dates</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-2">
                        <BarChart3 className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-2xl font-bold">
                            {gaps.length > 0 ? Math.round((withAssignment.length / gaps.length) * 100) : 0}%
                          </p>
                          <p className="text-xs text-muted-foreground">Assignment Rate</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
                {gaps.length === 0 ? (
                  <Card>
                    <CardContent className="flex flex-col items-center py-12 gap-2">
                      <CheckCircle2 className="h-8 w-8 text-green-500" />
                      <p className="text-muted-foreground">All controls are met — no gaps to remediate</p>
                    </CardContent>
                  </Card>
                ) : (
                  <div className="space-y-2">
                    {gaps
                      .sort((a, b) => {
                        /* 80.5 — sort by priority */
                        const prio: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
                        return (prio[a.priority || "low"] ?? 3) - (prio[b.priority || "low"] ?? 3);
                      })
                      .map((gap) => (
                        <Card key={gap.id} className="transition-all hover:shadow-sm">
                          <CardContent className="py-3">
                            <div className="flex items-center gap-4">
                              {statusIcon(gap.status)}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-xs text-muted-foreground">{gap.controlId}</span>
                                  <span className="font-medium text-sm truncate">{gap.title}</span>
                                  {/* 80.5 — priority badge */}
                                  {gap.priority && (
                                    <Badge
                                      variant={
                                        gap.priority === "critical"
                                          ? "destructive"
                                          : gap.priority === "high"
                                            ? "destructive"
                                            : "secondary"
                                      }
                                      className="text-[10px]"
                                    >
                                      {gap.priority}
                                    </Badge>
                                  )}
                                  {/* 80.4 — detection source badge */}
                                  {gap.detectionSource && (
                                    <Badge variant="outline" className="text-[10px]">
                                      {gap.detectionSource}
                                    </Badge>
                                  )}
                                </div>
                                <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                                  <span>{gap.frameworkId}</span>
                                  {gap.assignedTo && (
                                    <span className="flex items-center gap-1">
                                      <Users className="h-3 w-3" /> {gap.assignedTo}
                                    </span>
                                  )}
                                  {gap.remediationDueDate && (
                                    <span className="flex items-center gap-1">
                                      <Clock className="h-3 w-3" /> Due:{" "}
                                      {new Date(gap.remediationDueDate).toLocaleDateString()}
                                    </span>
                                  )}
                                  {gap.riskScore !== undefined && <span>Risk: {gap.riskScore}/10</span>}
                                </div>
                                {/* 80.2 — remediation progress bar */}
                                {gap.remediationProgress !== undefined && gap.remediationProgress > 0 && (
                                  <div className="mt-2">
                                    <Progress value={gap.remediationProgress} className="h-1.5" />
                                    <span className="text-[10px] text-muted-foreground">
                                      {gap.remediationProgress}% complete
                                    </span>
                                  </div>
                                )}
                              </div>
                              {gap.remediation && (
                                <Button variant="ghost" size="sm" className="text-xs">
                                  Fix <ArrowRight className="ml-1 h-3 w-3" />
                                </Button>
                              )}
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                  </div>
                )}
              </>
            );
          })()}
        </TabsContent>
      </Tabs>
    </div>
  );
}
