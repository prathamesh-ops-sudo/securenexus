import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import { Plug, ArrowDownToLine, FileWarning, Workflow, CheckCircle2, ArrowRight, X, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

interface GuidedStep {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  targetUrl: string;
  checkEndpoint: string;
  completedField: string;
}

const GUIDED_STEPS: GuidedStep[] = [
  {
    id: "first-connector",
    title: "Connect your first data source",
    description: "Set up a connector to start pulling security events from your SIEM, EDR, or cloud provider.",
    icon: Plug,
    targetUrl: "/connectors",
    checkEndpoint: "/api/connectors",
    completedField: "hasConnectors",
  },
  {
    id: "first-ingestion",
    title: "Verify data ingestion",
    description: "Confirm that alerts and events are flowing into the platform from your connected sources.",
    icon: ArrowDownToLine,
    targetUrl: "/ingestion",
    checkEndpoint: "/api/dashboard/stats",
    completedField: "hasIngestion",
  },
  {
    id: "first-incident",
    title: "Create or triage your first incident",
    description: "Review incoming alerts, correlate related events, and escalate to an incident for tracking.",
    icon: FileWarning,
    targetUrl: "/incidents",
    checkEndpoint: "/api/incidents",
    completedField: "hasIncidents",
  },
  {
    id: "first-playbook",
    title: "Run your first playbook",
    description: "Execute an automated response playbook to remediate threats or enrich investigation data.",
    icon: Workflow,
    targetUrl: "/playbooks",
    checkEndpoint: "/api/playbooks",
    completedField: "hasPlaybooks",
  },
];

const GUIDED_DISMISSED_KEY = "securenexus.guidedWorkflow.dismissed";
const GUIDED_COMPLETED_KEY = "securenexus.guidedWorkflow.completed";

function useGuidedProgress() {
  const { data: connectors } = useQuery<unknown[]>({
    queryKey: ["/api/connectors"],
  });

  const { data: stats } = useQuery<{ totalAlerts?: number }>({
    queryKey: ["/api/dashboard/stats"],
  });

  const { data: incidents } = useQuery<unknown[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: playbooks } = useQuery<unknown[]>({
    queryKey: ["/api/playbooks"],
  });

  const completedMap: Record<string, boolean> = {
    hasConnectors: Array.isArray(connectors) && connectors.length > 0,
    hasIngestion: (stats?.totalAlerts ?? 0) > 0,
    hasIncidents: Array.isArray(incidents) && incidents.length > 0,
    hasPlaybooks: Array.isArray(playbooks) && playbooks.length > 0,
  };

  return completedMap;
}

export function GuidedWorkflowBanner() {
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const [dismissed, setDismissed] = useState(false);
  const completedMap = useGuidedProgress();

  const steps = GUIDED_STEPS.map((step) => ({
    ...step,
    completed: completedMap[step.completedField] ?? false,
  }));

  const completedCount = steps.filter((s) => s.completed).length;
  const allDone = completedCount === steps.length;

  useEffect(() => {
    try {
      if (localStorage.getItem(GUIDED_DISMISSED_KEY) === "true") {
        setDismissed(true);
      }
    } catch {
      /* noop */
    }
  }, []);

  useEffect(() => {
    if (allDone) {
      try {
        localStorage.setItem(GUIDED_COMPLETED_KEY, "true");
      } catch {
        /* noop */
      }
    }
  }, [allDone]);

  if (!user || dismissed || allDone) return null;

  const nextStep = steps.find((s) => !s.completed);
  const pct = Math.round((completedCount / steps.length) * 100);

  function handleDismiss() {
    try {
      localStorage.setItem(GUIDED_DISMISSED_KEY, "true");
    } catch {
      /* noop */
    }
    setDismissed(true);
  }

  return (
    <Card className="mx-4 mt-4 md:mx-6 border-primary/20 bg-gradient-to-r from-primary/5 via-background to-primary/5">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-primary" aria-hidden="true" />
            <CardTitle className="text-base font-semibold">Quick Start Guide</CardTitle>
            <Badge variant="outline" className="text-[10px] px-1.5 h-4">
              {completedCount}/{steps.length}
            </Badge>
          </div>
          <button
            onClick={handleDismiss}
            className="p-1 rounded hover:bg-muted transition-colors"
            aria-label="Dismiss quick start guide"
          >
            <X className="h-4 w-4 text-muted-foreground" />
          </button>
        </div>
        <CardDescription className="text-xs">Complete these steps to get the most out of SecureNexus.</CardDescription>
        <Progress value={pct} className="h-1.5 mt-2" aria-label={`${pct}% complete`} />
      </CardHeader>
      <CardContent className="pb-4">
        <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-4">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <button
                key={step.id}
                onClick={() => {
                  if (!step.completed) navigate(step.targetUrl);
                }}
                disabled={step.completed}
                className={`flex items-start gap-3 p-3 rounded-lg border text-left transition-all ${
                  step.completed
                    ? "border-emerald-500/20 bg-emerald-500/5 opacity-70"
                    : nextStep?.id === step.id
                      ? "border-primary/30 bg-primary/5 hover:bg-primary/10 hover:border-primary/50"
                      : "border-border/50 hover:bg-muted/50"
                }`}
                aria-label={`Step ${idx + 1}: ${step.title}${step.completed ? " (completed)" : ""}`}
              >
                <div className="mt-0.5 shrink-0">
                  {step.completed ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  ) : (
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p
                    className={`text-sm font-medium leading-tight ${step.completed ? "line-through text-muted-foreground" : ""}`}
                  >
                    {step.title}
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed line-clamp-2">
                    {step.description}
                  </p>
                </div>
                {!step.completed && <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />}
              </button>
            );
          })}
        </div>
        {nextStep && (
          <div className="mt-3 flex justify-end">
            <Button size="sm" onClick={() => navigate(nextStep.targetUrl)}>
              <nextStep.icon className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
              {nextStep.title}
              <ArrowRight className="h-3.5 w-3.5 ml-1.5" aria-hidden="true" />
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
