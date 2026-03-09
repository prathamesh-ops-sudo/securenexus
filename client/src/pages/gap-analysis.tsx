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
} from "lucide-react";
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
}

interface Framework {
  id: string;
  name: string;
  version: string;
  controlCount: number;
  metCount: number;
  partialCount: number;
  notMetCount: number;
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
                      <CardTitle className="text-base">{f.name}</CardTitle>
                      <CardDescription>
                        {f.controlCount} controls &middot; v{f.version}
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
      </Tabs>
    </div>
  );
}
