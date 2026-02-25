import { useQuery, useMutation } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  CheckCircle2, Circle, ChevronDown, ChevronUp, X, Rocket, ArrowRight,
} from "lucide-react";

interface OnboardingStep {
  id: string;
  stepKey: string;
  stepLabel: string;
  stepDescription: string | null;
  category: string;
  sortOrder: number;
  isCompleted: boolean;
  completedAt: string | null;
  targetUrl: string | null;
}

interface OnboardingData {
  steps: OnboardingStep[];
  completedCount: number;
  totalSteps: number;
  pctComplete: number;
  allDone: boolean;
}

const DISMISSED_KEY = "securenexus.onboarding.dismissed.v1";

export function OnboardingChecklist() {
  const [, navigate] = useLocation();
  const [isOpen, setIsOpen] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(DISMISSED_KEY);
      if (raw === "true") setIsDismissed(true);
    } catch {}
  }, []);

  const { data, isLoading } = useQuery<OnboardingData>({
    queryKey: ["/api/onboarding-checklist"],
    enabled: !isDismissed,
    refetchInterval: 30000,
  });

  const completeMutation = useMutation({
    mutationFn: async (stepKey: string) => {
      const res = await apiRequest("POST", `/api/onboarding-checklist/${stepKey}/complete`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/onboarding-checklist"] });
    },
  });

  const dismissMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/onboarding-checklist/dismiss");
      return res.json();
    },
    onSuccess: () => {
      localStorage.setItem(DISMISSED_KEY, "true");
      setIsDismissed(true);
      setIsOpen(false);
    },
  });

  if (isDismissed || isLoading || !data || data.allDone) return null;

  const nextStep = data.steps.find(s => !s.isCompleted);

  return (
    <div className="fixed bottom-4 right-4 z-50 w-80">
      {!isOpen ? (
        <button
          onClick={() => setIsOpen(true)}
          className="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-gradient-to-r from-primary/90 to-primary text-primary-foreground shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Rocket className="h-5 w-5 shrink-0" />
          <div className="flex-1 text-left">
            <p className="text-sm font-medium">Get Started</p>
            <p className="text-xs opacity-80">{data.completedCount}/{data.totalSteps} steps complete</p>
          </div>
          <div className="relative h-8 w-8">
            <svg className="h-8 w-8 -rotate-90" viewBox="0 0 32 32">
              <circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.2" />
              <circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" strokeWidth="2"
                strokeDasharray={`${data.pctComplete * 0.88} 88`} strokeLinecap="round" />
            </svg>
            <span className="absolute inset-0 flex items-center justify-center text-[10px] font-bold">{data.pctComplete}%</span>
          </div>
        </button>
      ) : (
        <div className="rounded-xl border border-border/50 bg-background/95 backdrop-blur-xl shadow-2xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center justify-between bg-gradient-to-r from-primary/5 to-transparent">
            <div className="flex items-center gap-2">
              <Rocket className="h-4 w-4 text-primary" />
              <span className="text-sm font-semibold">Getting Started</span>
              <Badge variant="outline" className="text-[10px] px-1.5 h-4">{data.pctComplete}%</Badge>
            </div>
            <div className="flex items-center gap-1">
              <button onClick={() => setIsOpen(false)} className="p-1 rounded hover:bg-muted transition-colors">
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              </button>
              <button onClick={() => dismissMutation.mutate()} className="p-1 rounded hover:bg-muted transition-colors">
                <X className="h-4 w-4 text-muted-foreground" />
              </button>
            </div>
          </div>

          <div className="px-4 py-2">
            <Progress value={data.pctComplete} className="h-1.5" />
          </div>

          <div className="max-h-80 overflow-y-auto px-2 py-1">
            {data.steps.map(step => (
              <div
                key={step.stepKey}
                className={`flex items-start gap-3 px-2 py-2.5 rounded-lg transition-colors ${
                  step.isCompleted ? "opacity-60" : "hover:bg-muted/50 cursor-pointer"
                }`}
                onClick={() => {
                  if (!step.isCompleted && step.targetUrl) {
                    navigate(step.targetUrl);
                    setIsOpen(false);
                  }
                }}
              >
                <div className="mt-0.5 shrink-0">
                  {step.isCompleted ? (
                    <CheckCircle2 className="h-4.5 w-4.5 text-emerald-500" />
                  ) : (
                    <Circle className="h-4.5 w-4.5 text-muted-foreground" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${step.isCompleted ? "line-through text-muted-foreground" : ""}`}>
                    {step.stepLabel}
                  </p>
                  {step.stepDescription && (
                    <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{step.stepDescription}</p>
                  )}
                </div>
                {!step.isCompleted && step.targetUrl && (
                  <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />
                )}
              </div>
            ))}
          </div>

          <div className="px-4 py-2 border-t border-border/50">
            <button
              onClick={() => dismissMutation.mutate()}
              className="text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Dismiss checklist
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
