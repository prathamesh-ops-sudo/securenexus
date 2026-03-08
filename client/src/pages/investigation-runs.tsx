import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Search,
  Play,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Loader2,
  Eye,
  Bot,
  Shield,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";

interface Investigation {
  id: string;
  title: string;
  hypothesis: string;
  status: "running" | "completed" | "failed" | "pending_approval";
  confidence: number;
  findings: string[];
  actions: { description: string; status: string; requiresApproval: boolean }[];
  createdAt: string;
  completedAt?: string;
}

export default function InvestigationRunsPage() {
  usePageTitle("Investigation Runs");
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [hypothesis, setHypothesis] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const {
    data: investigations,
    isLoading,
    isError,
    refetch,
  } = useQuery<Investigation[]>({
    queryKey: ["/api/autonomous/investigations"],
    queryFn: () => apiRequest("GET", "/api/autonomous/investigations").then((r) => r.json()),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      apiRequest("POST", "/api/autonomous/investigations", {
        hypothesis,
        title: hypothesis.slice(0, 80),
      }),
    onSuccess: () => {
      toast({ title: "Investigation started" });
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/investigations"] });
      setShowCreate(false);
      setHypothesis("");
    },
    onError: () => toast({ title: "Failed to start investigation", variant: "destructive" }),
  });

  const list = Array.isArray(investigations) ? investigations : [];

  const statusIcon = (s: string) => {
    if (s === "running") return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
    if (s === "completed") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    if (s === "pending_approval") return <Shield className="h-4 w-4 text-yellow-500" />;
    return <Clock className="h-4 w-4 text-muted-foreground" />;
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load investigations</p>
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
            <Bot className="h-6 w-6" /> Investigation Runs
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Autonomous SOC investigations with human-in-the-loop approval gates
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
            <Play className="mr-2 h-4 w-4" /> New Investigation
          </Button>
        </div>
      </div>

      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Start Investigation</CardTitle>
            <CardDescription>Define a hypothesis for the autonomous SOC to investigate</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Hypothesis</Label>
              <Textarea
                value={hypothesis}
                onChange={(e) => setHypothesis(e.target.value)}
                placeholder="e.g. Lateral movement from compromised endpoint 10.0.1.42 to domain controller..."
                rows={3}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={() => createMutation.mutate()} disabled={!hypothesis.trim() || createMutation.isPending}>
                {createMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Play className="mr-2 h-4 w-4" />
                )}
                Start
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Activity className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((i) => i.status === "running").length}</p>
              <p className="text-xs text-muted-foreground">Running</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((i) => i.status === "completed").length}</p>
              <p className="text-xs text-muted-foreground">Completed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((i) => i.status === "pending_approval").length}</p>
              <p className="text-xs text-muted-foreground">Awaiting Approval</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <Bot className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">No investigations yet</p>
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <Play className="mr-2 h-4 w-4" /> Start First Investigation
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {list.map((inv) => (
            <Card
              key={inv.id}
              className="transition-all hover:shadow-md cursor-pointer"
              onClick={() => setExpandedId(expandedId === inv.id ? null : inv.id)}
            >
              <CardContent className="py-4">
                <div className="flex items-center gap-3">
                  {statusIcon(inv.status)}
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm truncate">{inv.title}</p>
                    <p className="text-xs text-muted-foreground truncate">{inv.hypothesis}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {inv.confidence > 0 && <Badge variant="outline">{inv.confidence}% confidence</Badge>}
                    <Badge
                      variant={
                        inv.status === "completed" ? "default" : inv.status === "failed" ? "destructive" : "secondary"
                      }
                    >
                      {inv.status.replace("_", " ")}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {new Date(inv.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                {expandedId === inv.id && (
                  <div className="mt-4 space-y-3 border-t pt-3">
                    {inv.findings && inv.findings.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Findings</p>
                        <ul className="space-y-1">
                          {inv.findings.map((f, i) => (
                            <li key={i} className="text-sm flex items-start gap-2">
                              <Eye className="h-3 w-3 mt-1 text-primary shrink-0" />
                              {f}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {inv.actions && inv.actions.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Actions</p>
                        <ul className="space-y-1">
                          {inv.actions.map((a, i) => (
                            <li key={i} className="text-sm flex items-center gap-2">
                              {a.requiresApproval ? (
                                <Shield className="h-3 w-3 text-yellow-500" />
                              ) : (
                                <CheckCircle2 className="h-3 w-3 text-green-500" />
                              )}
                              {a.description}
                              <Badge variant="outline" className="text-xs ml-auto">
                                {a.status}
                              </Badge>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
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
