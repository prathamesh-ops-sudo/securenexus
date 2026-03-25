import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  ClipboardCheck,
  Plus,
  RefreshCw,
  Trash2,
  ChevronRight,
  ArrowLeft,
  CheckCircle2,
  Circle,
  AlertTriangle,
  MinusCircle,
  HelpCircle,
  Shield,
  BarChart3,
  FileText,
  Save,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface Framework {
  id: string;
  name: string;
  description: string;
  controlCount: number;
}

interface Assessment {
  id: string;
  framework: string;
  title: string;
  description: string | null;
  status: string;
  totalControls: number;
  implementedControls: number;
  partialControls: number;
  notImplementedControls: number;
  notApplicableControls: number;
  overallScore: number;
  assessor: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

interface AssessmentResponse {
  id: string;
  controlId: string;
  controlTitle: string;
  controlDescription: string | null;
  category: string | null;
  status: string;
  notes: string | null;
  evidence: string | null;
  gapDescription: string | null;
  recommendedAction: string | null;
  priority: string | null;
  weight: number;
}

interface AssessmentDetail extends Assessment {
  responses: AssessmentResponse[];
}

const STATUS_ICONS: Record<string, React.ElementType> = {
  implemented: CheckCircle2,
  partially_implemented: MinusCircle,
  not_implemented: AlertTriangle,
  not_applicable: HelpCircle,
  not_assessed: Circle,
};

const STATUS_COLORS: Record<string, string> = {
  implemented: "text-green-500",
  partially_implemented: "text-yellow-500",
  not_implemented: "text-red-500",
  not_applicable: "text-zinc-400",
  not_assessed: "text-zinc-500",
};

const FRAMEWORK_COLORS: Record<string, string> = {
  cis_controls_v8: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  nist_csf_2: "bg-purple-500/10 text-purple-500 border-purple-500/20",
  iso_27001: "bg-green-500/10 text-green-500 border-green-500/20",
  soc2_type2: "bg-orange-500/10 text-orange-500 border-orange-500/20",
};

function CreateAssessmentDialog({ frameworks, onCreated }: { frameworks: Framework[]; onCreated: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [framework, setFramework] = useState("");
  const [title, setTitle] = useState("");

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/assessments", { framework, title: title || undefined });
      if (!res.ok) throw new Error("Failed to create assessment");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Assessment started" });
      setOpen(false);
      setFramework("");
      setTitle("");
      onCreated();
    },
    onError: () => toast({ title: "Error", description: "Failed to create assessment", variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" /> Start Assessment
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Start New Security Assessment</DialogTitle>
          <DialogDescription>Choose a framework to assess your organization against</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Framework *</Label>
            <Select value={framework} onValueChange={setFramework}>
              <SelectTrigger>
                <SelectValue placeholder="Select a framework" />
              </SelectTrigger>
              <SelectContent>
                {frameworks.map((f) => (
                  <SelectItem key={f.id} value={f.id}>
                    {f.name} ({f.controlCount} controls)
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Title (optional)</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Custom assessment title" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => createMutation.mutate()} disabled={!framework || createMutation.isPending}>
            {createMutation.isPending ? "Creating..." : "Start Assessment"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AssessmentDetailView({ assessmentId, onBack }: { assessmentId: string; onBack: () => void }) {
  const { toast } = useToast();
  const [expandedControl, setExpandedControl] = useState<string | null>(null);

  const {
    data: assessment,
    isLoading,
    refetch,
  } = useQuery<AssessmentDetail>({
    queryKey: ["/api/assessments", assessmentId],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/assessments/${assessmentId}`);
      return res.json();
    },
  });

  const updateResponseMutation = useMutation({
    mutationFn: async ({
      responseId,
      updates,
    }: {
      responseId: string;
      updates: Record<string, string | undefined>;
    }) => {
      const res = await apiRequest("PATCH", `/api/assessments/${assessmentId}/responses/${responseId}`, updates);
      if (!res.ok) throw new Error("Failed to update");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Control updated" });
      refetch();
    },
  });

  const completeMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/assessments/${assessmentId}/complete`);
      if (!res.ok) throw new Error("Failed to complete");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Assessment completed" });
      refetch();
    },
  });

  if (isLoading || !assessment) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  const responses = assessment.responses || [];
  const categories = Array.from(new Set(responses.map((r) => r.category || "General")));

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeft className="mr-2 h-4 w-4" /> Back
        </Button>
        <div className="flex-1">
          <h1 className="text-xl font-bold">{assessment.title}</h1>
          <p className="text-sm text-muted-foreground">{assessment.description}</p>
        </div>
        {assessment.status !== "completed" && (
          <Button size="sm" onClick={() => completeMutation.mutate()} disabled={completeMutation.isPending}>
            <CheckCircle2 className="mr-2 h-4 w-4" /> Complete Assessment
          </Button>
        )}
      </div>

      {/* Score Overview */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card className="col-span-2">
          <CardContent className="pt-4">
            <div className="flex items-center gap-4">
              <div className="relative w-16 h-16">
                <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-muted stroke-current"
                    strokeWidth="3"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className="text-primary stroke-current"
                    strokeWidth="3"
                    fill="none"
                    strokeDasharray={`${assessment.overallScore}, 100`}
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-lg font-bold">{assessment.overallScore}%</span>
                </div>
              </div>
              <div>
                <p className="font-semibold">Compliance Score</p>
                <p className="text-xs text-muted-foreground">{assessment.totalControls} total controls</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <CheckCircle2 className="h-4 w-4 text-green-500" />
            <p className="text-xl font-bold">{assessment.implementedControls}</p>
            <p className="text-[10px] text-muted-foreground">Implemented</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <MinusCircle className="h-4 w-4 text-yellow-500 mb-1" />
            <p className="text-xl font-bold">{assessment.partialControls}</p>
            <p className="text-[10px] text-muted-foreground">Partial</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <AlertTriangle className="h-4 w-4 text-red-500 mb-1" />
            <p className="text-xl font-bold">{assessment.notImplementedControls}</p>
            <p className="text-[10px] text-muted-foreground">Not Impl.</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <HelpCircle className="h-4 w-4 text-zinc-400 mb-1" />
            <p className="text-xl font-bold">{assessment.notApplicableControls}</p>
            <p className="text-[10px] text-muted-foreground">N/A</p>
          </CardContent>
        </Card>
      </div>

      <Progress value={assessment.overallScore} className="h-2" />

      {/* Controls by Category */}
      {categories.map((cat) => {
        const catResponses = responses.filter((r) => (r.category || "General") === cat);
        return (
          <Card key={cat}>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">{cat}</CardTitle>
              <CardDescription>{catResponses.length} controls</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1">
              {catResponses.map((resp) => {
                const StatusIcon = STATUS_ICONS[resp.status] || Circle;
                const isExpanded = expandedControl === resp.id;
                return (
                  <div key={resp.id} className="border rounded-lg">
                    <button
                      className="w-full flex items-center gap-3 p-3 text-left hover:bg-muted/50 transition-colors"
                      onClick={() => setExpandedControl(isExpanded ? null : resp.id)}
                    >
                      <StatusIcon className={`h-5 w-5 shrink-0 ${STATUS_COLORS[resp.status]}`} />
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium">
                          {resp.controlId}: {resp.controlTitle}
                        </span>
                      </div>
                      <Badge variant="outline" className="text-[10px]">
                        {resp.status.replace(/_/g, " ")}
                      </Badge>
                      <ChevronRight className={`h-4 w-4 transition-transform ${isExpanded ? "rotate-90" : ""}`} />
                    </button>
                    {isExpanded && (
                      <div className="px-3 pb-3 pt-0 border-t space-y-3">
                        <p className="text-sm text-muted-foreground">{resp.controlDescription}</p>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <Label className="text-xs">Status</Label>
                            <Select
                              value={resp.status}
                              onValueChange={(v) =>
                                updateResponseMutation.mutate({ responseId: resp.id, updates: { status: v } })
                              }
                            >
                              <SelectTrigger className="h-8 text-xs">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="not_assessed">Not Assessed</SelectItem>
                                <SelectItem value="implemented">Implemented</SelectItem>
                                <SelectItem value="partially_implemented">Partially Implemented</SelectItem>
                                <SelectItem value="not_implemented">Not Implemented</SelectItem>
                                <SelectItem value="not_applicable">Not Applicable</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label className="text-xs">Priority</Label>
                            <Select
                              value={resp.priority || "medium"}
                              onValueChange={(v) =>
                                updateResponseMutation.mutate({ responseId: resp.id, updates: { priority: v } })
                              }
                            >
                              <SelectTrigger className="h-8 text-xs">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="critical">Critical</SelectItem>
                                <SelectItem value="high">High</SelectItem>
                                <SelectItem value="medium">Medium</SelectItem>
                                <SelectItem value="low">Low</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        <div>
                          <Label className="text-xs">Notes / Evidence</Label>
                          <Textarea
                            defaultValue={resp.notes || ""}
                            placeholder="Describe the current implementation status, evidence, or gaps..."
                            rows={2}
                            className="text-xs"
                            onBlur={(e) => {
                              if (e.target.value !== (resp.notes || "")) {
                                updateResponseMutation.mutate({
                                  responseId: resp.id,
                                  updates: { notes: e.target.value },
                                });
                              }
                            }}
                          />
                        </div>
                        {(resp.status === "not_implemented" || resp.status === "partially_implemented") && (
                          <div>
                            <Label className="text-xs">Gap / Recommended Action</Label>
                            <Textarea
                              defaultValue={resp.gapDescription || ""}
                              placeholder="Describe the gap and recommended remediation..."
                              rows={2}
                              className="text-xs"
                              onBlur={(e) => {
                                if (e.target.value !== (resp.gapDescription || "")) {
                                  updateResponseMutation.mutate({
                                    responseId: resp.id,
                                    updates: { gapDescription: e.target.value },
                                  });
                                }
                              }}
                            />
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

export default function SecurityAssessmentsPage() {
  usePageTitle("Security Assessments");
  const [selectedAssessment, setSelectedAssessment] = useState<string | null>(null);

  const { data: frameworks } = useQuery<Framework[]>({
    queryKey: ["/api/assessments/frameworks"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/assessments/frameworks");
      return res.json();
    },
  });

  const {
    data: assessments,
    isLoading,
    refetch,
  } = useQuery<Assessment[]>({
    queryKey: ["/api/assessments"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/assessments");
      return res.json();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("DELETE", `/api/assessments/${id}`);
      if (!res.ok) throw new Error("Failed to delete");
    },
    onSuccess: () => refetch(),
  });

  if (selectedAssessment) {
    return (
      <AssessmentDetailView
        assessmentId={selectedAssessment}
        onBack={() => {
          setSelectedAssessment(null);
          refetch();
        }}
      />
    );
  }

  const list = assessments || [];

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-40" />
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
            <ClipboardCheck className="h-6 w-6" /> Security Assessments
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Assess your organization against industry frameworks like CIS, NIST, ISO 27001, and SOC 2
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <CreateAssessmentDialog frameworks={frameworks || []} onCreated={() => refetch()} />
        </div>
      </div>

      {/* 75.1 — Assessment Summary Dashboard */}
      {list.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total Assessments</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-2xl font-bold">{list.filter((a) => a.status === "completed").length}</p>
              <p className="text-xs text-muted-foreground">Completed</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-2xl font-bold">
                {list.length > 0 ? Math.round(list.reduce((s, a) => s + a.overallScore, 0) / list.length) : 0}%
              </p>
              <p className="text-xs text-muted-foreground">Average Score</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-2xl font-bold">{list.reduce((s, a) => s + a.notImplementedControls, 0)}</p>
              <p className="text-xs text-muted-foreground">Open Gaps</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* 75.2 — Framework Templates with control counts */}
      <div>
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          Available Frameworks
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {(frameworks || []).map((fw) => {
            const fwAssessments = list.filter((a) => a.framework === fw.id);
            const latestScore = fwAssessments.length > 0 ? fwAssessments[fwAssessments.length - 1].overallScore : null;
            return (
              <Card key={fw.id} className="hover:shadow-sm transition-shadow">
                <CardContent className="pt-4">
                  <Badge className={FRAMEWORK_COLORS[fw.id] || ""} variant="outline">
                    {fw.name}
                  </Badge>
                  <p className="text-xs text-muted-foreground mt-2 line-clamp-2">{fw.description}</p>
                  <div className="flex items-center justify-between mt-2">
                    <p className="text-xs text-muted-foreground">{fw.controlCount} controls</p>
                    {latestScore !== null && (
                      <Badge
                        variant={latestScore >= 80 ? "default" : latestScore >= 50 ? "secondary" : "destructive"}
                        className="text-[10px]"
                      >
                        Last: {latestScore}%
                      </Badge>
                    )}
                  </div>
                  {fwAssessments.length > 0 && (
                    <p className="text-[10px] text-muted-foreground mt-1">{fwAssessments.length} assessment(s) run</p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Assessments List */}
      <div>
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Your Assessments</h2>
        {list.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center py-16 gap-4">
              <ClipboardCheck className="h-12 w-12 text-muted-foreground/40" />
              <div className="text-center">
                <h3 className="font-semibold">No assessments yet</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Start your first security assessment against an industry framework
                </p>
              </div>
              <CreateAssessmentDialog frameworks={frameworks || []} onCreated={() => refetch()} />
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {list.map((a) => (
              <Card
                key={a.id}
                className="hover:shadow-md transition-shadow cursor-pointer"
                onClick={() => setSelectedAssessment(a.id)}
              >
                <CardContent className="pt-4">
                  <div className="flex items-start justify-between mb-3">
                    <Badge className={FRAMEWORK_COLORS[a.framework] || ""} variant="outline">
                      {a.framework.replace(/_/g, " ").toUpperCase()}
                    </Badge>
                    <Badge variant={a.status === "completed" ? "default" : "secondary"}>
                      {a.status.replace(/_/g, " ")}
                    </Badge>
                  </div>
                  <h3 className="font-semibold text-sm mb-1">{a.title}</h3>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="flex-1">
                      <Progress value={a.overallScore} className="h-2" />
                    </div>
                    <span className="text-sm font-bold">{a.overallScore}%</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3 text-green-500" /> {a.implementedControls}
                    </span>
                    <span className="flex items-center gap-1">
                      <MinusCircle className="h-3 w-3 text-yellow-500" /> {a.partialControls}
                    </span>
                    <span className="flex items-center gap-1">
                      <AlertTriangle className="h-3 w-3 text-red-500" /> {a.notImplementedControls}
                    </span>
                    <span className="text-[10px] ml-auto">{new Date(a.createdAt).toLocaleDateString()}</span>
                  </div>
                  <div className="flex items-center justify-between mt-3 pt-2 border-t">
                    <span className="text-xs text-muted-foreground">{a.assessor || "Unknown"}</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteMutation.mutate(a.id);
                      }}
                    >
                      <Trash2 className="h-3 w-3 mr-1" /> Delete
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
