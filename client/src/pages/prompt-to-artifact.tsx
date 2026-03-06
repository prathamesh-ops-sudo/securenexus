import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bell,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  FileText,
  Loader2,
  MessageSquare,
  Search,
  Send,
  Sparkles,
  Target,
  Workflow,
  X,
  Zap,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

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
  createdAt: string;
  completedAt: string | null;
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

function StepIndicator({ step }: { step: InvestigationStep }) {
  return (
    <div className="flex items-start gap-3 py-2">
      <div className="mt-0.5">
        {step.status === "completed" ? (
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
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

function ArtifactDisplay({ artifact }: { artifact: GeneratedArtifact }) {
  const [expanded, setExpanded] = useState(false);
  const config = ARTIFACT_TYPE_CONFIG[artifact.type];
  const Icon = config?.icon || Search;

  return (
    <Card>
      <div className="flex items-start gap-3 p-4 cursor-pointer hover-elevate" onClick={() => setExpanded(!expanded)}>
        <div className={`p-2 rounded-md border shrink-0 ${config?.color || "bg-muted"}`}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold truncate">{artifact.name}</h3>
            <Badge variant="outline" className={`text-[10px] shrink-0 ${config?.color || ""}`}>
              {config?.label || artifact.type}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{artifact.description}</p>
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
        <div className="border-t border-border/50 p-4">
          <p className="text-xs font-medium mb-2">Artifact Configuration</p>
          <pre className="p-3 rounded-md bg-muted/30 border text-[11px] font-mono overflow-x-auto max-h-80 overflow-y-auto">
            {JSON.stringify(artifact.content, null, 2)}
          </pre>
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

  return (
    <Card className="overflow-hidden" data-testid={`investigation-${investigation.id}`}>
      <div className="flex items-start gap-3 p-4 cursor-pointer hover-elevate" onClick={onToggle}>
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
          </div>
          {investigation.summary && <p className="text-xs text-muted-foreground mt-1">{investigation.summary}</p>}
          <p className="text-[10px] text-muted-foreground mt-1">
            {new Date(investigation.createdAt).toLocaleString()} · {investigation.steps.length} steps ·{" "}
            {investigation.artifacts.length} artifact(s)
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

          {investigation.artifacts.length > 0 && (
            <div>
              <p className="text-xs font-medium mb-2">Generated Artifacts</p>
              <div className="space-y-2">
                {investigation.artifacts.map((artifact) => (
                  <ArtifactDisplay key={artifact.id} artifact={artifact} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export default function PromptToArtifactPage() {
  const [prompt, setPrompt] = useState("");
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: suggestions } = useQuery<string[]>({
    queryKey: ["/api/prompt-artifact/suggestions"],
  });

  const { data: investigations, isLoading } = useQuery<Investigation[]>({
    queryKey: ["/api/prompt-artifact/investigations"],
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
      setExpandedIds((prev) => new Set(prev).add(data.id));
      setPrompt("");
      toast({
        title: "Investigation complete",
        description: `Generated ${data.artifacts.length} artifact(s)`,
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
    if (trimmed.length === 0) return;
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
            Ask a question in natural language — get dashboards, alert rules, workflows, and investigations
          </p>
        </div>
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
              {prompt.length}/2000 · Press Enter to submit, Shift+Enter for new line
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
    </div>
  );
}
