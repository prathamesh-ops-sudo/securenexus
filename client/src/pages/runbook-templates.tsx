import { useState } from "react";
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
  Edit,
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
  title: string;
  description: string;
  type: "manual" | "automated" | "approval";
  order: number;
}

interface RunbookTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  steps: RunbookStep[];
  createdAt: string;
  updatedAt: string;
}

export default function RunbookTemplatesPage() {
  usePageTitle("Runbook Templates");
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newCategory, setNewCategory] = useState("incident-response");
  const [newSeverity, setNewSeverity] = useState("medium");
  const [editSteps, setEditSteps] = useState<Partial<RunbookStep>[]>([]);

  const {
    data: templates,
    isLoading,
    isError,
    refetch,
  } = useQuery<RunbookTemplate[]>({
    queryKey: ["/api/runbook-templates"],
    queryFn: () => apiRequest("GET", "/api/runbook-templates").then((r) => r.json()),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const steps = editSteps.map((s, i) => ({
        title: s.title || `Step ${i + 1}`,
        description: s.description || "",
        type: s.type || "manual",
        order: i,
      }));
      return apiRequest("POST", "/api/runbook-templates", {
        name: newName,
        description: newDesc,
        category: newCategory,
        severity: newSeverity,
        steps,
      });
    },
    onSuccess: () => {
      toast({ title: "Runbook template created" });
      queryClient.invalidateQueries({ queryKey: ["/api/runbook-templates"] });
      setShowCreate(false);
      setNewName("");
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

  const addStep = () => {
    setEditSteps([...editSteps, { title: "", description: "", type: "manual" }]);
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

  if (isLoading) {
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

  const list = Array.isArray(templates) ? templates : [];

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
                <Label>Name</Label>
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Ransomware Response"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label>Category</Label>
                  <Select value={newCategory} onValueChange={setNewCategory}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="incident-response">Incident Response</SelectItem>
                      <SelectItem value="threat-hunting">Threat Hunting</SelectItem>
                      <SelectItem value="compliance">Compliance</SelectItem>
                      <SelectItem value="disaster-recovery">Disaster Recovery</SelectItem>
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
                        value={step.type || "manual"}
                        onValueChange={(v) => {
                          const arr = [...editSteps];
                          arr[idx] = { ...arr[idx], type: v as RunbookStep["type"] };
                          setEditSteps(arr);
                        }}
                      >
                        <SelectTrigger className="w-36">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="manual">Manual</SelectItem>
                          <SelectItem value="automated">Automated</SelectItem>
                          <SelectItem value="approval">Approval</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Textarea
                      placeholder="Step description..."
                      value={step.description || ""}
                      onChange={(e) => {
                        const arr = [...editSteps];
                        arr[idx] = { ...arr[idx], description: e.target.value };
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
              <Button onClick={() => createMutation.mutate()} disabled={!newName.trim() || createMutation.isPending}>
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
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <Plus className="mr-2 h-4 w-4" /> Create First Template
            </Button>
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
                      <CardTitle className="text-base">{t.name}</CardTitle>
                      <CardDescription className="text-xs">{t.description}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{t.category}</Badge>
                    <Badge variant={t.severity === "critical" ? "destructive" : "secondary"}>{t.severity}</Badge>
                    <Badge variant="outline">
                      {t.steps?.length || 0} step{(t.steps?.length || 0) !== 1 ? "s" : ""}
                    </Badge>
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
                    {expandedId === t.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>
              </CardHeader>
              {expandedId === t.id && (
                <CardContent>
                  <div className="space-y-2 mt-2">
                    {(t.steps || []).map((step, idx) => (
                      <div key={step.id || idx} className="flex items-start gap-3 p-3 border rounded-lg">
                        <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/10 text-primary text-sm font-medium shrink-0">
                          {idx + 1}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-sm">{step.title}</span>
                            <Badge variant="outline" className="text-xs">
                              {step.type === "automated" ? (
                                <Play className="mr-1 h-3 w-3" />
                              ) : step.type === "approval" ? (
                                <CheckCircle2 className="mr-1 h-3 w-3" />
                              ) : (
                                <Edit className="mr-1 h-3 w-3" />
                              )}
                              {step.type}
                            </Badge>
                          </div>
                          {step.description && <p className="text-xs text-muted-foreground mt-1">{step.description}</p>}
                        </div>
                      </div>
                    ))}
                    {(!t.steps || t.steps.length === 0) && (
                      <p className="text-sm text-muted-foreground text-center py-4">No steps defined</p>
                    )}
                  </div>
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
