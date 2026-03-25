import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  BookOpen,
  Plus,
  Trash2,
  Play,
  GripVertical,
  CheckCircle2,
  Clock,
  AlertTriangle,
  RefreshCw,
  Loader2,
  ChevronDown,
  ChevronUp,
  FileText,
  Sparkles,
  Tag,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface RunbookStep {
  id: string;
  templateId: string;
  stepOrder: number;
  title: string;
  instructions: string | null;
  actionType: string | null;
  isRequired: boolean | null;
  estimatedMinutes: number | null;
  createdAt: string | null;
}

interface RunbookTemplate {
  id: string;
  orgId: string | null;
  incidentType: string;
  title: string;
  description: string | null;
  severity: string | null;
  estimatedDuration: string | null;
  tags: string[] | null;
  isBuiltIn: boolean | null;
  createdAt: string | null;
  updatedAt: string | null;
  steps?: RunbookStep[];
}

export default function RunbookTemplatesPage() {
  usePageTitle("Runbook Templates");
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newIncidentType, setNewIncidentType] = useState("general");
  const [newSeverity, setNewSeverity] = useState("medium");
  const [editSteps, setEditSteps] = useState<Partial<RunbookStep>[]>([]);
  const [seeded, setSeeded] = useState(false);

  const {
    data: templates,
    isPending,
    isError,
    refetch,
  } = useQuery<RunbookTemplate[]>({
    queryKey: ["/api/runbook-templates"],
    queryFn: () => apiRequest("GET", "/api/runbook-templates").then((r) => r.json()),
  });

  const seedMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/runbook-templates/seed"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/runbook-templates"] });
      toast({ title: "Built-in templates seeded" });
      setSeeded(true);
    },
    onError: () => toast({ title: "Failed to seed templates", variant: "destructive" }),
  });

  const list = Array.isArray(templates) ? templates : [];

  useEffect(() => {
    if (templates && Array.isArray(templates) && templates.length === 0 && !seeded && !seedMutation.isPending) {
      seedMutation.mutate();
    }
  }, [templates, seeded, seedMutation.isPending]);

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/runbook-templates", {
        title: newTitle,
        description: newDesc,
        incidentType: newIncidentType,
        severity: newSeverity,
      });
      const template = await res.json();
      for (let i = 0; i < editSteps.length; i++) {
        const s = editSteps[i];
        await apiRequest("POST", `/api/runbook-templates/${template.id}/steps`, {
          title: s.title || `Step ${i + 1}`,
          instructions: s.instructions || "",
          actionType: s.actionType || "manual",
          stepOrder: i + 1,
          isRequired: true,
        });
      }
      return template;
    },
    onSuccess: () => {
      toast({ title: "Runbook template created" });
      queryClient.invalidateQueries({ queryKey: ["/api/runbook-templates"] });
      setShowCreate(false);
      setNewTitle("");
      setNewDesc("");
      setEditSteps([]);
    },
    onError: () => toast({ title: "Failed to create template", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/runbook-templates/${id}`),
    onSuccess: () => {
      toast({ title: "Template deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/runbook-templates"] });
    },
    onError: () => toast({ title: "Failed to delete", variant: "destructive" }),
  });

  const { data: expandedTemplate, isPending: expandedPending } = useQuery<RunbookTemplate & { steps: RunbookStep[] }>({
    queryKey: ["/api/runbook-templates", expandedId],
    queryFn: () => apiRequest("GET", `/api/runbook-templates/${expandedId}`).then((r) => r.json()),
    enabled: !!expandedId,
  });

  const addStep = () => {
    setEditSteps([...editSteps, { title: "", instructions: "", actionType: "manual" }]);
  };

  const removeStep = (idx: number) => {
    setEditSteps(editSteps.filter((_, i) => i !== idx));
  };

  const moveStep = (idx: number, dir: "up" | "down") => {
    const arr = [...editSteps];
    const swapIdx = dir === "up" ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= arr.length) return;
    [arr[idx], arr[swapIdx]] = [arr[swapIdx], arr[idx]];
    setEditSteps(arr);
  };

  if (isPending) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-4">
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
            <p className="text-muted-foreground">Failed to load runbook templates</p>
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
            <BookOpen className="h-6 w-6" /> Runbook Templates
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Create and manage step-by-step runbook templates for incident response
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
            {seedMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="mr-2 h-4 w-4" />
            )}
            Seed Built-in
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
            <Plus className="mr-2 h-4 w-4" /> New Template
          </Button>
        </div>
      </div>

      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Create Runbook Template</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Title</Label>
                <Input
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Ransomware Response"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label>Incident Type</Label>
                  <Select value={newIncidentType} onValueChange={setNewIncidentType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="general">General</SelectItem>
                      <SelectItem value="brute_force">Brute Force</SelectItem>
                      <SelectItem value="malware">Malware</SelectItem>
                      <SelectItem value="phishing">Phishing</SelectItem>
                      <SelectItem value="data_exfiltration">Data Exfiltration</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                      <SelectItem value="ddos">DDoS</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Severity</Label>
                  <Select value={newSeverity} onValueChange={setNewSeverity}>
                    <SelectTrigger>
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
            </div>
            <div>
              <Label>Description</Label>
              <Textarea
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Describe the runbook purpose..."
                rows={2}
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Steps ({editSteps.length})</Label>
                <Button variant="outline" size="sm" onClick={addStep}>
                  <Plus className="mr-1 h-3 w-3" /> Add Step
                </Button>
              </div>
              {editSteps.map((step, idx) => (
                <div key={idx} className="flex items-start gap-2 border rounded-lg p-3">
                  <div className="flex flex-col gap-1 pt-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5"
                      onClick={() => moveStep(idx, "up")}
                      disabled={idx === 0}
                    >
                      <ChevronUp className="h-3 w-3" />
                    </Button>
                    <GripVertical className="h-4 w-4 text-muted-foreground" />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5"
                      onClick={() => moveStep(idx, "down")}
                      disabled={idx === editSteps.length - 1}
                    >
                      <ChevronDown className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="flex-1 space-y-2">
                    <div className="flex gap-2">
                      <Input
                        placeholder={`Step ${idx + 1} title`}
                        value={step.title || ""}
                        onChange={(e) => {
                          const arr = [...editSteps];
                          arr[idx] = { ...arr[idx], title: e.target.value };
                          setEditSteps(arr);
                        }}
                        className="flex-1"
                      />
                      <Select
                        value={step.actionType || "manual"}
                        onValueChange={(v) => {
                          const arr = [...editSteps];
                          arr[idx] = { ...arr[idx], actionType: v };
                          setEditSteps(arr);
                        }}
                      >
                        <SelectTrigger className="w-44">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="manual">Manual</SelectItem>
                          <SelectItem value="gather_alerts">Gather Alerts</SelectItem>
                          <SelectItem value="block_ip">Block IP</SelectItem>
                          <SelectItem value="block_domain">Block Domain</SelectItem>
                          <SelectItem value="isolate_host">Isolate Host</SelectItem>
                          <SelectItem value="disable_user">Disable User</SelectItem>
                          <SelectItem value="quarantine_file">Quarantine File</SelectItem>
                          <SelectItem value="correlate_evidence">Correlate Evidence</SelectItem>
                          <SelectItem value="ai_analysis">AI Analysis</SelectItem>
                          <SelectItem value="action_taken">Action Taken</SelectItem>
                          <SelectItem value="recommendation">Recommendation</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Textarea
                      placeholder="Step instructions..."
                      value={step.instructions || ""}
                      onChange={(e) => {
                        const arr = [...editSteps];
                        arr[idx] = { ...arr[idx], instructions: e.target.value };
                        setEditSteps(arr);
                      }}
                      rows={1}
                    />
                  </div>
                  <Button variant="ghost" size="icon" className="text-destructive" onClick={() => removeStep(idx)}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={() => createMutation.mutate()} disabled={!newTitle.trim() || createMutation.isPending}>
                {createMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Create Template
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <FileText className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">No runbook templates yet</p>
            {seedMutation.isPending ? (
              <p className="text-xs text-muted-foreground flex items-center gap-1">
                <Loader2 className="h-3 w-3 animate-spin" /> Seeding built-in templates...
              </p>
            ) : (
              <Button size="sm" onClick={() => seedMutation.mutate()}>
                <Sparkles className="mr-2 h-4 w-4" /> Seed Built-in Templates
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {list.map((t) => (
            <Card key={t.id} className="transition-all hover:shadow-md">
              <CardHeader
                className="pb-2 cursor-pointer"
                onClick={() => setExpandedId(expandedId === t.id ? null : t.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <BookOpen className="h-5 w-5 text-primary" />
                    <div>
                      <CardTitle className="text-base">{t.title}</CardTitle>
                      <CardDescription className="text-xs">{t.description}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {t.isBuiltIn && (
                      <Badge variant="outline">
                        <Sparkles className="mr-1 h-3 w-3" /> Built-in
                      </Badge>
                    )}
                    <Badge variant="outline">{t.incidentType.replace(/_/g, " ")}</Badge>
                    <Badge variant={t.severity === "critical" ? "destructive" : "secondary"}>{t.severity}</Badge>
                    {t.estimatedDuration && (
                      <Badge variant="outline">
                        <Clock className="mr-1 h-3 w-3" /> {t.estimatedDuration}
                      </Badge>
                    )}
                    {t.tags && t.tags.length > 0 && (
                      <Badge variant="outline">
                        <Tag className="mr-1 h-3 w-3" /> {t.tags.length} tags
                      </Badge>
                    )}
                    {!t.isBuiltIn && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteMutation.mutate(t.id);
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                    {expandedId === t.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>
              </CardHeader>
              {expandedId === t.id && (
                <CardContent>
                  {expandedPending ? (
                    <div className="space-y-2 mt-2">
                      {[1, 2, 3].map((i) => (
                        <Skeleton key={i} className="h-16" />
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-2 mt-2">
                      {(expandedTemplate?.steps || []).map((step, idx) => (
                        <div key={step.id || idx} className="flex items-start gap-3 p-3 border rounded-lg">
                          <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/10 text-primary text-sm font-medium shrink-0">
                            {step.stepOrder || idx + 1}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm">{step.title}</span>
                              {step.actionType && (
                                <Badge variant="outline" className="text-xs">
                                  {step.actionType === "ai_analysis" ? (
                                    <Sparkles className="mr-1 h-3 w-3" />
                                  ) : step.actionType === "recommendation" ? (
                                    <CheckCircle2 className="mr-1 h-3 w-3" />
                                  ) : (
                                    <Play className="mr-1 h-3 w-3" />
                                  )}
                                  {step.actionType.replace(/_/g, " ")}
                                </Badge>
                              )}
                              {step.isRequired && (
                                <Badge variant="secondary" className="text-xs">
                                  Required
                                </Badge>
                              )}
                              {step.estimatedMinutes && (
                                <Badge variant="outline" className="text-xs">
                                  <Clock className="mr-1 h-3 w-3" /> {step.estimatedMinutes}m
                                </Badge>
                              )}
                            </div>
                            {step.instructions && (
                              <p className="text-xs text-muted-foreground mt-1">{step.instructions}</p>
                            )}
                          </div>
                        </div>
                      ))}
                      {(!expandedTemplate?.steps || expandedTemplate.steps.length === 0) && (
                        <p className="text-sm text-muted-foreground text-center py-4">No steps defined</p>
                      )}
                    </div>
                  )}
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
