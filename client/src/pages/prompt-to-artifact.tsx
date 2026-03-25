import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  BarChart3,
  Bell,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Code2,
  Database,
  Edit3,
  FileText,
  Loader2,
  MessageSquare,
  Save,
  Search,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Workflow,
  X,
  Star,
  StarOff,
  Share2,
  Rocket,
  Undo2,
  ShieldQuestion,
  ArrowRight,
  Copy,
  Eye,
  Filter,
  Heart,
  Layers,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface SourceCitation {
  id: string;
  source: string;
  description: string;
  dataPoints: number;
  confidence: number;
  retrievedAt: string;
}

interface QueryPlanStep {
  id: string;
  type: string;
  description: string;
  params: Record<string, unknown>;
  estimatedCost: string;
  citations: string[];
}

interface ApprovalGate {
  id: string;
  artifactId: string;
  reason: string;
  requiredRole: string;
  status: string;
  requestedBy: string;
  requestedAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNotes: string | null;
}

interface EditableLogicBlock {
  id: string;
  label: string;
  language: string;
  code: string;
  description: string;
  editable: boolean;
}

interface InvestigationStep {
  id: string;
  label: string;
  description: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
  result: Record<string, unknown> | null;
}

interface GeneratedArtifact {
  id: string;
  type: string;
  name: string;
  description: string;
  content: Record<string, unknown>;
  editableLogic: EditableLogicBlock[];
  citations: SourceCitation[];
  approvalGate: ApprovalGate | null;
  templateId: string | null;
  queryPlan: QueryPlanStep[];
  createdAt: string;
}

interface Investigation {
  id: string;
  orgId: string | null;
  prompt: string;
  intent: string;
  status: string;
  steps: InvestigationStep[];
  artifacts: GeneratedArtifact[];
  summary: string | null;
  citations: SourceCitation[];
  createdAt: string;
  completedAt: string | null;
}

// ═══════════════════════════════════════════════════════════════════════════
// 32.1 Artifact Type Selection
// ═══════════════════════════════════════════════════════════════════════════

interface ArtifactTypeTemplate {
  type: string;
  label: string;
  description: string;
  examplePrompts: string[];
  bestPractices: string[];
}

// ═══════════════════════════════════════════════════════════════════════════
// 32.2 Artifact Preview
// ═══════════════════════════════════════════════════════════════════════════

interface ValidationResult {
  valid: boolean;
  errors: { field: string; message: string; severity: "error" | "warning" }[];
  artifactType: string;
  checkedAt: string;
}

interface DeploymentRecord {
  id: string;
  artifactId: string;
  investigationId: string;
  artifactType: string;
  targetPage: string;
  status: "pending" | "deployed" | "rolled_back" | "failed";
  deployedAt: string;
  rolledBackAt: string | null;
  deployedBy: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// 32.3 Prompt History & Favorites
// ═══════════════════════════════════════════════════════════════════════════

interface PromptHistoryEntry {
  id: string;
  orgId: string;
  prompt: string;
  artifactType: string;
  isFavorite: boolean;
  sharedWith: string[];
  usedAt: string;
  resultId: string | null;
}

const ARTIFACT_TYPE_CONFIG: Record<string, { icon: typeof BarChart3; color: string; label: string }> = {
  dashboard: {
    icon: BarChart3,
    color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
    label: "Dashboard",
  },
  alert_rule: {
    icon: Bell,
    color: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    label: "Alert Rule",
  },
  workflow: {
    icon: Workflow,
    color: "text-purple-400 bg-purple-500/10 border-purple-500/20",
    label: "Workflow",
  },
  investigation: {
    icon: Target,
    color: "text-red-400 bg-red-500/10 border-red-500/20",
    label: "Investigation",
  },
  report: {
    icon: FileText,
    color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    label: "Report",
  },
  query: {
    icon: Search,
    color: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    label: "Query",
  },
};

const INTENT_LABELS: Record<string, string> = {
  create_dashboard: "Create Dashboard",
  create_alert_rule: "Create Alert Rule",
  create_workflow: "Create Workflow",
  run_investigation: "Run Investigation",
  generate_report: "Generate Report",
  run_query: "Run Query",
};

const APPROVAL_STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof ShieldCheck }> = {
  pending_approval: {
    label: "Pending Approval",
    color: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    icon: ShieldAlert,
  },
  approved: {
    label: "Approved",
    color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    icon: ShieldCheck,
  },
  rejected: {
    label: "Rejected",
    color: "text-red-400 bg-red-500/10 border-red-500/20",
    icon: X,
  },
};

function StepIndicator({ step }: { step: InvestigationStep }) {
  return (
    <div className="flex items-start gap-3 py-2">
      <div className="mt-0.5">
        {step.status === "completed" ? (
          <CheckCircle2 className="h-4 w-4 text-green-500" />
        ) : step.status === "running" ? (
          <Loader2 className="h-4 w-4 text-cyan-400 animate-spin" />
        ) : (
          <Clock className="h-4 w-4 text-muted-foreground" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium">{step.label}</p>
        <p className="text-[10px] text-muted-foreground mt-0.5">{step.description}</p>
        {step.result && (
          <div className="mt-1.5 p-2 rounded-md bg-muted/30 border text-[10px] font-mono">
            {Object.entries(step.result).map(([key, value]) => (
              <div key={key} className="flex gap-2">
                <span className="text-muted-foreground">{key}:</span>
                <span>{Array.isArray(value) ? value.join(", ") : String(value)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function CitationsSection({ citations }: { citations: SourceCitation[] }) {
  if (citations.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5">
        <Database className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium">Source Citations ({citations.length})</span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {citations.map((c) => (
          <div key={c.id} className="p-2.5 rounded-md border bg-muted/20 text-[11px] space-y-1">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium truncate">{c.source}</span>
              <Badge variant="outline" className="text-[9px] shrink-0">
                {Math.round(c.confidence * 100)}% confidence
              </Badge>
            </div>
            <p className="text-muted-foreground leading-relaxed">{c.description}</p>
            <div className="flex items-center gap-3 text-muted-foreground">
              <span>{c.dataPoints.toLocaleString()} data points</span>
              <span>Retrieved {new Date(c.retrievedAt).toLocaleTimeString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ApprovalGateSection({
  gate,
  onReview,
  isReviewing,
}: {
  gate: ApprovalGate;
  onReview: (decision: "approved" | "rejected", notes: string) => void;
  isReviewing: boolean;
}) {
  const [notes, setNotes] = useState("");
  const statusConfig = APPROVAL_STATUS_CONFIG[gate.status];
  const StatusIcon = statusConfig?.icon || ShieldAlert;

  return (
    <div className="p-3 rounded-md border border-amber-500/30 bg-amber-500/5 space-y-3">
      <div className="flex items-center gap-2">
        <StatusIcon className={`h-4 w-4 ${statusConfig?.color?.split(" ")[0] || "text-amber-400"}`} />
        <span className="text-xs font-bold">Approval Gate</span>
        <Badge variant="outline" className={`text-[10px] ${statusConfig?.color || ""}`}>
          {statusConfig?.label || gate.status}
        </Badge>
      </div>
      <p className="text-[11px] text-muted-foreground">{gate.reason}</p>
      <div className="text-[10px] text-muted-foreground">
        Required role: <span className="font-medium text-foreground">{gate.requiredRole}</span>
      </div>

      {gate.status === "pending_approval" && (
        <div className="space-y-2 pt-1">
          <Textarea
            placeholder="Review notes (optional)"
            className="min-h-[60px] text-xs resize-none"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            maxLength={2000}
            aria-label="Approval review notes"
          />
          <div className="flex gap-2">
            <Button
              size="sm"
              className="h-7 text-xs bg-emerald-600 hover:bg-emerald-700"
              onClick={() => onReview("approved", notes)}
              disabled={isReviewing}
              aria-label="Approve artifact"
            >
              {isReviewing ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Check className="h-3 w-3 mr-1" />}
              Approve
            </Button>
            <Button
              size="sm"
              variant="destructive"
              className="h-7 text-xs"
              onClick={() => onReview("rejected", notes)}
              disabled={isReviewing}
              aria-label="Reject artifact"
            >
              {isReviewing ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <X className="h-3 w-3 mr-1" />}
              Reject
            </Button>
          </div>
        </div>
      )}

      {gate.reviewedBy && (
        <div className="text-[10px] text-muted-foreground pt-1 border-t border-border/30">
          Reviewed by <span className="font-medium text-foreground">{gate.reviewedBy}</span> on{" "}
          {new Date(gate.reviewedAt || "").toLocaleString()}
          {gate.reviewNotes && <p className="mt-1 italic">&quot;{gate.reviewNotes}&quot;</p>}
        </div>
      )}
    </div>
  );
}

function EditableLogicSection({
  blocks,
  investigationId,
  artifactId,
}: {
  blocks: EditableLogicBlock[];
  investigationId: string;
  artifactId: string;
}) {
  const [editingBlockId, setEditingBlockId] = useState<string | null>(null);
  const [editCode, setEditCode] = useState("");
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const updateMutation = useMutation({
    mutationFn: async ({ blockId, newCode }: { blockId: string; newCode: string }) => {
      const res = await apiRequest("POST", "/api/prompt-artifact/artifacts/update-logic", {
        investigationId,
        artifactId,
        blockId,
        newCode,
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["/api/prompt-artifact/investigations"],
      });
      setEditingBlockId(null);
      toast({
        title: "Logic updated",
        description: "Artifact logic block has been saved.",
      });
    },
    onError: () => {
      toast({
        title: "Update failed",
        description: "Could not save logic changes.",
        variant: "destructive",
      });
    },
  });

  const LANGUAGE_LABELS: Record<string, string> = {
    json: "JSON",
    kql: "KQL",
    sql: "SQL",
    yaml: "YAML",
    pseudocode: "Pseudocode",
  };

  if (blocks.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5">
        <Code2 className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium">Editable Logic ({blocks.length} blocks)</span>
      </div>
      <div className="space-y-2">
        {blocks.map((block) => {
          const isEditing = editingBlockId === block.id;
          return (
            <div key={block.id} className="rounded-md border overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 bg-muted/30 border-b">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium">{block.label}</span>
                  <Badge variant="outline" className="text-[9px]">
                    {LANGUAGE_LABELS[block.language] || block.language}
                  </Badge>
                </div>
                {block.editable && (
                  <div>
                    {isEditing ? (
                      <div className="flex gap-1">
                        <Button
                          size="sm"
                          className="h-6 text-[10px] px-2"
                          onClick={() =>
                            updateMutation.mutate({
                              blockId: block.id,
                              newCode: editCode,
                            })
                          }
                          disabled={updateMutation.isPending}
                          aria-label="Save changes"
                        >
                          {updateMutation.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Save className="h-3 w-3 mr-1" />
                          )}
                          Save
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-6 text-[10px] px-2"
                          onClick={() => setEditingBlockId(null)}
                          aria-label="Cancel editing"
                        >
                          Cancel
                        </Button>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-6 text-[10px] px-2"
                        onClick={() => {
                          setEditingBlockId(block.id);
                          setEditCode(block.code);
                        }}
                        aria-label={`Edit ${block.label}`}
                      >
                        <Edit3 className="h-3 w-3 mr-1" />
                        Edit
                      </Button>
                    )}
                  </div>
                )}
              </div>
              <div className="p-0">
                {isEditing ? (
                  <Textarea
                    className="min-h-[120px] rounded-none border-0 text-[11px] font-mono resize-y focus-visible:ring-0"
                    value={editCode}
                    onChange={(e) => setEditCode(e.target.value)}
                    maxLength={50000}
                    aria-label={`Edit ${block.label} code`}
                  />
                ) : (
                  <pre className="p-3 text-[11px] font-mono overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">
                    {block.code}
                  </pre>
                )}
              </div>
              <div className="px-3 py-1.5 bg-muted/20 border-t">
                <p className="text-[10px] text-muted-foreground">{block.description}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ArtifactDisplay({ artifact, investigationId }: { artifact: GeneratedArtifact; investigationId: string }) {
  const [expanded, setExpanded] = useState(false);
  const config = ARTIFACT_TYPE_CONFIG[artifact.type];
  const Icon = config?.icon || Search;
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const reviewMutation = useMutation({
    mutationFn: async ({ decision, notes }: { decision: "approved" | "rejected"; notes: string }) => {
      if (!artifact.approvalGate) throw new Error("No approval gate");
      const res = await apiRequest("POST", `/api/prompt-artifact/approvals/${artifact.approvalGate.id}/review`, {
        reviewerName: "Current User",
        decision,
        notes,
      });
      return res.json();
    },
    onSuccess: (_data: unknown, variables: { decision: "approved" | "rejected"; notes: string }) => {
      queryClient.invalidateQueries({
        queryKey: ["/api/prompt-artifact/investigations"],
      });
      queryClient.invalidateQueries({
        queryKey: ["/api/prompt-artifact/approvals/pending"],
      });
      toast({
        title: variables.decision === "approved" ? "Artifact approved" : "Artifact rejected",
        description:
          variables.decision === "approved"
            ? "The artifact has been approved for activation."
            : "The artifact has been rejected.",
      });
    },
    onError: () => {
      toast({
        title: "Review failed",
        description: "Could not submit approval review.",
        variant: "destructive",
      });
    },
  });

  return (
    <Card>
      <div
        className="flex items-start gap-3 p-4 cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
        aria-expanded={expanded}
        aria-label={`${artifact.name} - click to ${expanded ? "collapse" : "expand"}`}
      >
        <div className={`p-2 rounded-md border shrink-0 ${config?.color || "bg-muted"}`}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-sm font-bold truncate">{artifact.name}</h3>
            <Badge variant="outline" className={`text-[10px] shrink-0 ${config?.color || ""}`}>
              {config?.label || artifact.type}
            </Badge>
            {artifact.templateId && (
              <Badge variant="outline" className="text-[9px] shrink-0 text-muted-foreground">
                {artifact.templateId}
              </Badge>
            )}
            {artifact.approvalGate && (
              <Badge
                variant="outline"
                className={`text-[10px] shrink-0 ${APPROVAL_STATUS_CONFIG[artifact.approvalGate.status]?.color || ""}`}
              >
                {APPROVAL_STATUS_CONFIG[artifact.approvalGate.status]?.label || artifact.approvalGate.status}
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{artifact.description}</p>
          <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
            <span>{artifact.citations.length} citations</span>
            <span>{artifact.editableLogic.length} editable blocks</span>
            {artifact.queryPlan.length > 0 && <span>{artifact.queryPlan.length} query steps</span>}
          </div>
        </div>
        <div className="shrink-0">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border/50 p-4 space-y-4">
          {artifact.approvalGate && (
            <ApprovalGateSection
              gate={artifact.approvalGate}
              onReview={(decision, notes) => reviewMutation.mutate({ decision, notes })}
              isReviewing={reviewMutation.isPending}
            />
          )}

          <CitationsSection citations={artifact.citations} />

          <EditableLogicSection
            blocks={artifact.editableLogic}
            investigationId={investigationId}
            artifactId={artifact.id}
          />

          <div>
            <p className="text-xs font-medium mb-2">Raw Configuration</p>
            <pre className="p-3 rounded-md bg-muted/30 border text-[11px] font-mono overflow-x-auto max-h-60 overflow-y-auto">
              {JSON.stringify(artifact.content, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </Card>
  );
}

function InvestigationCard({
  investigation,
  isExpanded,
  onToggle,
}: {
  investigation: Investigation;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const firstArtifact = investigation.artifacts[0];
  const artifactConfig = firstArtifact ? ARTIFACT_TYPE_CONFIG[firstArtifact.type] : null;
  const ArtifactIcon = artifactConfig?.icon || Search;
  const hasApproval = investigation.artifacts.some((a) => a.approvalGate !== null);
  const pendingApproval = investigation.artifacts.some((a) => a.approvalGate?.status === "pending_approval");

  return (
    <Card className="overflow-hidden" data-testid={`investigation-${investigation.id}`}>
      <div
        className="flex items-start gap-3 p-4 cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={onToggle}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
        aria-expanded={isExpanded}
      >
        <div
          className={`p-2 rounded-md border shrink-0 ${artifactConfig?.color || "text-muted-foreground bg-muted/50"}`}
        >
          <ArtifactIcon className="h-4 w-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-bold truncate max-w-md">{investigation.prompt}</p>
            <Badge variant="outline" className="text-[10px] shrink-0">
              {INTENT_LABELS[investigation.intent] || investigation.intent}
            </Badge>
            <Badge
              variant="outline"
              className={`text-[10px] shrink-0 ${
                investigation.status === "completed"
                  ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                  : investigation.status === "running"
                    ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
                    : investigation.status === "failed"
                      ? "text-red-400 bg-red-500/10 border-red-500/20"
                      : ""
              }`}
            >
              {investigation.status}
            </Badge>
            {pendingApproval && (
              <Badge
                variant="outline"
                className="text-[10px] shrink-0 text-amber-400 bg-amber-500/10 border-amber-500/20"
              >
                Needs Approval
              </Badge>
            )}
            {hasApproval && !pendingApproval && (
              <Badge
                variant="outline"
                className="text-[10px] shrink-0 text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
              >
                Reviewed
              </Badge>
            )}
          </div>
          {investigation.summary && <p className="text-xs text-muted-foreground mt-1">{investigation.summary}</p>}
          <p className="text-[10px] text-muted-foreground mt-1">
            {new Date(investigation.createdAt).toLocaleString()} &middot; {investigation.steps.length} steps &middot;{" "}
            {investigation.artifacts.length} artifact(s) &middot; {investigation.citations.length} citations
          </p>
        </div>
        <div className="shrink-0">
          {isExpanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </div>

      {isExpanded && (
        <div className="border-t border-border/50 p-4 space-y-4">
          <div>
            <p className="text-xs font-medium mb-2">Investigation Steps</p>
            <div className="space-y-0.5 border-l-2 border-border/50 pl-3 ml-1">
              {investigation.steps.map((step) => (
                <StepIndicator key={step.id} step={step} />
              ))}
            </div>
          </div>

          {investigation.citations.length > 0 && <CitationsSection citations={investigation.citations} />}

          {investigation.artifacts.length > 0 && (
            <div>
              <p className="text-xs font-medium mb-2">Generated Artifacts</p>
              <div className="space-y-2">
                {investigation.artifacts.map((artifact) => (
                  <ArtifactDisplay key={artifact.id} artifact={artifact} investigationId={investigation.id} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 32.1 Artifact Type Selection Component
// ═══════════════════════════════════════════════════════════════════════════

const ARTIFACT_TYPE_ICONS: Record<string, typeof ShieldAlert> = {
  alert_rule: ShieldAlert,
  workflow: Workflow,
  report: FileText,
  query: Search,
  dashboard: BarChart3,
  investigation: ShieldCheck,
};

function ArtifactTypeSelector({
  onSelect,
  onPromptSet,
}: {
  onSelect: (type: string) => void;
  onPromptSet: (prompt: string) => void;
}) {
  const { data: artifactTypes } = useQuery<ArtifactTypeTemplate[]>({
    queryKey: ["/api/prompt-artifact/artifact-types"],
  });
  const [selectedType, setSelectedType] = useState<string | null>(null);

  if (!artifactTypes) return null;

  const selected = artifactTypes.find((t) => t.type === selectedType);

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-primary" />
          <CardTitle className="text-sm font-medium">Choose Artifact Type</CardTitle>
        </div>
        <CardDescription className="text-xs">Select what you want to generate</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2 mb-3">
          {artifactTypes.map((at) => {
            const Icon = ARTIFACT_TYPE_ICONS[at.type] || Target;
            const isSelected = selectedType === at.type;
            return (
              <button
                key={at.type}
                onClick={() => {
                  setSelectedType(at.type);
                  onSelect(at.type);
                }}
                className={`p-2.5 rounded-md border text-left transition-colors ${
                  isSelected ? "border-primary bg-primary/5" : "border-muted-foreground/10 hover:bg-muted/30"
                }`}
              >
                <Icon className={`h-4 w-4 mb-1 ${isSelected ? "text-primary" : "text-muted-foreground"}`} />
                <p className="text-xs font-medium">{at.label}</p>
                <p className="text-[10px] text-muted-foreground line-clamp-1">{at.description}</p>
              </button>
            );
          })}
        </div>

        {selected && (
          <div className="space-y-3 border-t pt-3">
            <div>
              <p className="text-xs font-medium mb-1.5">Example Prompts</p>
              <div className="space-y-1">
                {selected.examplePrompts.map((ep, i) => (
                  <button
                    key={i}
                    onClick={() => onPromptSet(ep)}
                    className="w-full text-left px-2.5 py-1.5 rounded text-xs hover:bg-muted/30 transition-colors border border-transparent hover:border-muted-foreground/10 flex items-center gap-2"
                  >
                    <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
                    <span>{ep}</span>
                  </button>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs font-medium mb-1.5">Best Practices</p>
              <ul className="space-y-0.5">
                {selected.bestPractices.map((bp, i) => (
                  <li key={i} className="text-[10px] text-muted-foreground flex items-start gap-1.5">
                    <Check className="h-3 w-3 text-emerald-500 shrink-0 mt-0.5" />
                    <span>{bp}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 32.2 Artifact Preview with Syntax Highlighting
// ═══════════════════════════════════════════════════════════════════════════

function ArtifactPreviewPanel({ investigation }: { investigation: Investigation }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const validateMutation = useMutation({
    mutationFn: async (params: { investigationId: string; artifactId: string }) => {
      const res = await apiRequest("POST", "/api/prompt-artifact/artifacts/validate", params);
      return (await res.json()) as ValidationResult;
    },
  });

  const deployMutation = useMutation({
    mutationFn: async (params: { investigationId: string; artifactId: string }) => {
      const res = await apiRequest("POST", "/api/prompt-artifact/artifacts/deploy", params);
      return (await res.json()) as DeploymentRecord;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/prompt-artifact/deployments"] });
      toast({ title: "Artifact deployed", description: `Deployed to ${data.targetPage}` });
    },
    onError: () => toast({ title: "Deploy failed", variant: "destructive" }),
  });

  if (investigation.artifacts.length === 0) return null;

  return (
    <div className="space-y-3">
      {investigation.artifacts.map((artifact) => {
        const contentStr = JSON.stringify(artifact.content, null, 2);
        return (
          <Card key={artifact.id}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Eye className="h-4 w-4 text-primary" />
                  <CardTitle className="text-sm">{artifact.name}</CardTitle>
                </div>
                <div className="flex items-center gap-1.5">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() =>
                      validateMutation.mutate({
                        investigationId: investigation.id,
                        artifactId: artifact.id,
                      })
                    }
                    disabled={validateMutation.isPending}
                  >
                    {validateMutation.isPending ? (
                      <Loader2 className="h-3 w-3 animate-spin mr-1" />
                    ) : (
                      <ShieldQuestion className="h-3 w-3 mr-1" />
                    )}
                    Validate
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => {
                      navigator.clipboard.writeText(contentStr);
                      toast({ title: "Copied to clipboard" });
                    }}
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy
                  </Button>
                  <Button
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() =>
                      deployMutation.mutate({
                        investigationId: investigation.id,
                        artifactId: artifact.id,
                      })
                    }
                    disabled={deployMutation.isPending}
                  >
                    {deployMutation.isPending ? (
                      <Loader2 className="h-3 w-3 animate-spin mr-1" />
                    ) : (
                      <Rocket className="h-3 w-3 mr-1" />
                    )}
                    Deploy
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Validation results */}
              {validateMutation.data && (
                <div
                  className={`mb-3 p-2.5 rounded-md border text-xs ${
                    validateMutation.data.valid
                      ? "border-emerald-500/20 bg-emerald-500/5"
                      : "border-red-500/20 bg-red-500/5"
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    {validateMutation.data.valid ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                    ) : (
                      <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                    )}
                    <span className="font-medium">
                      {validateMutation.data.valid ? "Validation Passed" : "Validation Failed"}
                    </span>
                  </div>
                  {validateMutation.data.errors.length > 0 && (
                    <ul className="space-y-0.5 mt-1">
                      {validateMutation.data.errors.map((err, i) => (
                        <li key={i} className="flex items-start gap-1">
                          {err.severity === "error" ? (
                            <X className="h-3 w-3 text-red-500 shrink-0 mt-0.5" />
                          ) : (
                            <AlertTriangle className="h-3 w-3 text-amber-500 shrink-0 mt-0.5" />
                          )}
                          <span>
                            <strong>{err.field}:</strong> {err.message}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Code preview with syntax highlighting simulation */}
              <div className="relative">
                <pre className="bg-muted/30 rounded-md p-3 text-xs font-mono overflow-x-auto max-h-[300px] overflow-y-auto border border-muted-foreground/10">
                  <code>{contentStr}</code>
                </pre>
                <Badge variant="outline" className="absolute top-2 right-2 text-[9px]">
                  {artifact.type.replace(/_/g, " ").toUpperCase()}
                </Badge>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 32.3 Prompt History & Favorites Component
// ═══════════════════════════════════════════════════════════════════════════

function PromptHistoryPanel({ onSelect }: { onSelect: (prompt: string) => void }) {
  const [historySearch, setHistorySearch] = useState("");
  const [showFavoritesOnly, setShowFavoritesOnly] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: history } = useQuery<PromptHistoryEntry[]>({
    queryKey: ["/api/prompt-artifact/history", historySearch, showFavoritesOnly],
  });

  const toggleFavoriteMutation = useMutation({
    mutationFn: async (promptId: string) => {
      const res = await apiRequest("POST", "/api/prompt-artifact/history/toggle-favorite", { promptId });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/prompt-artifact/history"] });
    },
  });

  const shareMutation = useMutation({
    mutationFn: async (promptId: string) => {
      const res = await apiRequest("POST", "/api/prompt-artifact/history/share", {
        promptId,
        shareWith: ["team"],
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Prompt shared", description: "Team members can now see this prompt" });
      queryClient.invalidateQueries({ queryKey: ["/api/prompt-artifact/history"] });
    },
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-medium">Prompt History</CardTitle>
          </div>
          <Button
            variant={showFavoritesOnly ? "default" : "outline"}
            size="sm"
            className="h-7 text-xs"
            onClick={() => setShowFavoritesOnly(!showFavoritesOnly)}
          >
            <Heart className={`h-3 w-3 mr-1 ${showFavoritesOnly ? "fill-current" : ""}`} />
            Favorites
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="relative mb-3">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search prompts..."
            className="h-8 pl-8 text-xs"
            value={historySearch}
            onChange={(e) => setHistorySearch(e.target.value)}
          />
        </div>

        {!history || history.length === 0 ? (
          <div className="text-center py-4">
            <Clock className="h-6 w-6 text-muted-foreground/30 mx-auto mb-1" />
            <p className="text-xs text-muted-foreground">
              {showFavoritesOnly ? "No favorite prompts yet" : "No prompt history yet"}
            </p>
          </div>
        ) : (
          <ScrollArea className="max-h-[200px]">
            <div className="space-y-1.5">
              {history.map((entry) => (
                <div
                  key={entry.id}
                  className="flex items-center gap-2 p-2 rounded-md border border-muted-foreground/10 hover:bg-muted/30 transition-colors group"
                >
                  <button onClick={() => onSelect(entry.prompt)} className="flex-1 text-left text-xs line-clamp-1">
                    {entry.prompt}
                  </button>
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => toggleFavoriteMutation.mutate(entry.id)}
                      className="p-1 hover:bg-muted rounded"
                    >
                      {entry.isFavorite ? (
                        <Star className="h-3 w-3 text-amber-400 fill-amber-400" />
                      ) : (
                        <StarOff className="h-3 w-3 text-muted-foreground" />
                      )}
                    </button>
                    <button onClick={() => shareMutation.mutate(entry.id)} className="p-1 hover:bg-muted rounded">
                      <Share2 className="h-3 w-3 text-muted-foreground" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}

export default function PromptToArtifactPage() {
  const [prompt, setPrompt] = useState("");
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [selectedArtifactType, setSelectedArtifactType] = useState<string | null>(null);

  const { data: deployments } = useQuery<DeploymentRecord[]>({
    queryKey: ["/api/prompt-artifact/deployments"],
  });
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: suggestions } = useQuery<string[]>({
    queryKey: ["/api/prompt-artifact/suggestions"],
  });

  const { data: investigations, isLoading } = useQuery<Investigation[]>({
    queryKey: ["/api/prompt-artifact/investigations"],
  });

  const { data: pendingApprovals } = useQuery<ApprovalGate[]>({
    queryKey: ["/api/prompt-artifact/approvals/pending"],
  });

  const runMutation = useMutation({
    mutationFn: async (promptText: string) => {
      const res = await apiRequest("POST", "/api/prompt-artifact/investigate", { prompt: promptText });
      return res.json();
    },
    onSuccess: (data: Investigation) => {
      queryClient.invalidateQueries({
        queryKey: ["/api/prompt-artifact/investigations"],
      });
      queryClient.invalidateQueries({
        queryKey: ["/api/prompt-artifact/approvals/pending"],
      });
      setExpandedIds((prev) => new Set(prev).add(data.id));
      setPrompt("");
      toast({
        title: "Investigation complete",
        description: `Generated ${data.artifacts.length} artifact(s) with ${data.citations.length} source citations`,
      });
    },
    onError: () => {
      toast({
        title: "Investigation failed",
        description: "An error occurred while processing your request.",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = useCallback(() => {
    const trimmed = prompt.trim();
    if (trimmed.length === 0 || runMutation.isPending) return;
    runMutation.mutate(trimmed);
  }, [prompt, runMutation]);

  const handleSuggestionClick = useCallback((suggestion: string) => {
    setPrompt(suggestion);
  }, []);

  const toggleExpanded = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const pendingCount = pendingApprovals?.length || 0;

  return (
    <div className="w-full p-4 md:p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-md bg-purple-500/10 border border-purple-500/20">
              <Sparkles className="h-5 w-5 text-purple-400" />
            </div>
            <h1 className="text-xl font-bold" data-testid="text-page-title">
              Prompt-to-Artifact Engine
            </h1>
          </div>
          <p className="text-sm text-muted-foreground" data-testid="text-page-description">
            Natural-language security builder with constrained generation, source citations, and approval gates
          </p>
        </div>
        {pendingCount > 0 && (
          <Badge variant="outline" className="text-xs text-amber-400 bg-amber-500/10 border-amber-500/20">
            <AlertTriangle className="h-3 w-3 mr-1" />
            {pendingCount} pending approval
            {pendingCount !== 1 ? "s" : ""}
          </Badge>
        )}
      </div>

      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="relative">
            <Textarea
              placeholder="Ask a security question... e.g. 'Show me a dashboard of critical alerts from the last 24 hours'"
              className="min-h-[80px] pr-12 resize-none text-sm"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSubmit();
                }
              }}
              maxLength={2000}
              data-testid="input-prompt"
              aria-label="Security question prompt"
            />
            <Button
              size="icon"
              className="absolute bottom-3 right-3 h-8 w-8"
              onClick={handleSubmit}
              disabled={prompt.trim().length === 0 || runMutation.isPending}
              aria-label="Submit prompt"
              data-testid="button-submit"
            >
              {runMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </Button>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-muted-foreground">
              {prompt.length}/2000 &middot; Press Enter to submit, Shift+Enter for new line
            </span>
            {runMutation.isPending && (
              <span className="text-[10px] text-cyan-400 flex items-center gap-1">
                <Loader2 className="h-3 w-3 animate-spin" />
                Analyzing...
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {suggestions && suggestions.length > 0 && (
        <div>
          <div className="flex items-center gap-1.5 mb-2">
            <MessageSquare className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-xs font-medium text-muted-foreground">Suggested Prompts</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {suggestions.map((suggestion, i) => (
              <button
                key={i}
                className="px-3 py-1.5 rounded-full border text-xs hover:bg-accent/50 transition-colors text-left"
                onClick={() => handleSuggestionClick(suggestion)}
                aria-label={`Use suggestion: ${suggestion}`}
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* 32.1 Artifact Type Selection */}
      <ArtifactTypeSelector onSelect={setSelectedArtifactType} onPromptSet={setPrompt} />

      {/* 32.3 Prompt History & Favorites */}
      <PromptHistoryPanel onSelect={setPrompt} />

      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {Object.entries(ARTIFACT_TYPE_CONFIG).map(([type, config]) => {
          const count = investigations
            ? investigations.filter((inv) => inv.artifacts.length > 0 && inv.artifacts[0].type === type).length
            : 0;
          return (
            <Card key={type}>
              <CardContent className="p-3 text-center">
                <div className={`p-1.5 rounded-md border inline-flex mb-1 ${config.color}`}>
                  <config.icon className="h-3.5 w-3.5" />
                </div>
                <p className="text-lg font-bold">{count}</p>
                <p className="text-[10px] text-muted-foreground">{config.label}s</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div>
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="h-4 w-4 text-muted-foreground" />
          <h2 className="text-sm font-bold">Investigation History</h2>
          {investigations && (
            <Badge variant="outline" className="text-[10px]">
              {investigations.length}
            </Badge>
          )}
        </div>

        {isLoading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <Card key={i}>
                <CardContent className="p-4">
                  <Skeleton className="h-16 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : !investigations || investigations.length === 0 ? (
          <Card>
            <CardContent className="p-8 text-center">
              <Sparkles className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">No investigations yet</p>
              <p className="text-xs text-muted-foreground mt-1">
                Enter a security question above to generate your first artifact.
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {investigations.map((investigation) => (
              <InvestigationCard
                key={investigation.id}
                investigation={investigation}
                isExpanded={expandedIds.has(investigation.id)}
                onToggle={() => toggleExpanded(investigation.id)}
              />
            ))}
          </div>
        )}
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════
        32.2 Artifact Preview for Latest Investigation
        ═══════════════════════════════════════════════════════════════════════ */}
      {investigations && investigations.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Eye className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-sm font-bold">Artifact Preview &amp; Deployment</h2>
          </div>
          <ArtifactPreviewPanel investigation={investigations[0]} />
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════════
        32.5 Deployment Pipeline
        ═══════════════════════════════════════════════════════════════════════ */}
      {deployments && deployments.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Rocket className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-medium">Deployment History</CardTitle>
              <Badge variant="outline" className="text-[10px]">
                {deployments.length}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {deployments.slice(0, 5).map((d) => (
                <div
                  key={d.id}
                  className="flex items-center justify-between p-2 rounded-md border border-muted-foreground/10"
                >
                  <div className="flex items-center gap-2">
                    <Badge
                      variant="outline"
                      className={`text-[9px] ${
                        d.status === "deployed"
                          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                          : d.status === "rolled_back"
                            ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                            : "text-red-400 bg-red-500/10 border-red-500/20"
                      }`}
                    >
                      {d.status}
                    </Badge>
                    <span className="text-xs">{d.targetPage}</span>
                    <span className="text-[10px] text-muted-foreground">
                      {new Date(d.deployedAt).toLocaleDateString()}
                    </span>
                  </div>
                  {d.status === "deployed" && (
                    <Badge variant="outline" className="text-[9px] text-muted-foreground">
                      <Undo2 className="h-2.5 w-2.5 mr-0.5" />
                      Rollback available
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
