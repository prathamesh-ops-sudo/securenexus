import { useState, useEffect, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  CreditCard,
  Users,
  Plug,
  Compass,
  Check,
  ChevronRight,
  ChevronLeft,
  SkipForward,
  X,
  Plus,
  Trash2,
  Sparkles,
  ArrowRight,
  Shield,
  BarChart3,
  Bell,
  Search,
  Settings,
  Navigation,
  Loader2,
  Save,
  AlertCircle,
  ListChecks,
  PlayCircle,
  BookOpen,
  Scan,
  UserPlus,
  Clock,
  TrendingUp,
} from "lucide-react";

interface WizardStatus {
  currentStep: number;
  completedSteps: string[];
  skippedSteps: string[];
  orgId?: string;
  totalSteps: number;
  isComplete: boolean;
  tourCompleted: boolean;
  steps: string[];
  /* 86.1 — server-side progress persistence */
  savedProgress?: Record<string, unknown>;
  lastSavedAt?: string;
  /* 86.5 — onboarding analytics */
  analytics?: {
    startedAt?: string;
    stepTimestamps?: Record<string, string>;
    dropOffStep?: string;
  };
}

interface WizardOptions {
  industries: string[];
  companySizes: string[];
  plans: { id: string; name: string; price: number; features: string[] }[];
}

interface InvitationEntry {
  email: string;
  role: string;
}

const STEP_CONFIG = [
  { key: "choose_plan", label: "Choose Plan", icon: CreditCard, description: "Select your subscription" },
  { key: "invite_team", label: "Invite Team", icon: Users, description: "Add your colleagues" },
  { key: "connect_integration", label: "Connect Integration", icon: Plug, description: "Link your tools" },
  { key: "dashboard_tour", label: "Dashboard Tour", icon: Compass, description: "Learn the platform" },
];

function StepProgressBar({
  currentStep,
  completedSteps,
  totalSteps,
}: {
  currentStep: number;
  completedSteps: string[];
  totalSteps: number;
}) {
  const percent = totalSteps > 0 ? (completedSteps.length / totalSteps) * 100 : 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">Setup Progress</span>
        <span className="font-medium">
          {completedSteps.length} of {totalSteps} steps
        </span>
      </div>
      <Progress value={percent} className="h-2" />
      <div className="flex items-center gap-1">
        {STEP_CONFIG.map((step, index) => {
          const isCompleted = completedSteps.includes(step.key);
          const isCurrent = index === currentStep;
          const Icon = step.icon;

          return (
            <div key={step.key} className="flex items-center flex-1">
              <div className="flex flex-col items-center flex-1">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-xs transition-all ${
                    isCompleted
                      ? "bg-emerald-500/20 text-emerald-500 border border-emerald-500/30"
                      : isCurrent
                        ? "bg-primary/20 text-primary border border-primary/30 ring-2 ring-primary/20"
                        : "bg-muted/50 text-muted-foreground border border-border/50"
                  }`}
                >
                  {isCompleted ? <Check className="h-3.5 w-3.5" /> : <Icon className="h-3.5 w-3.5" />}
                </div>
                <span
                  className={`text-[10px] mt-1 text-center leading-tight ${isCurrent ? "text-primary font-medium" : "text-muted-foreground"}`}
                >
                  {step.label}
                </span>
              </div>
              {index < STEP_CONFIG.length - 1 && (
                <div className={`h-px w-full mx-1 ${isCompleted ? "bg-emerald-500/50" : "bg-border/50"}`} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ChoosePlanStep({
  options,
  onSelect,
  onSkip,
  isLoading,
}: {
  options: WizardOptions | undefined;
  onSelect: (planId: string) => void;
  onSkip: () => void;
  isLoading: boolean;
}) {
  const [selected, setSelected] = useState("free");

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Choose Your Plan</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Start free and upgrade anytime. All plans include core security features.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {options?.plans.map((plan) => (
          <Card
            data-testid="onboarding-wizard-card-1"
            key={plan.id}
            className={`cursor-pointer transition-all hover:shadow-md ${
              selected === plan.id ? "border-primary ring-2 ring-primary/20" : "border-border/50 hover:border-border"
            }`}
            onClick={() => setSelected(plan.id)}
          >
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">{plan.name}</CardTitle>
                {plan.id === "growth" && (
                  <Badge variant="secondary" className="text-[10px]">
                    Most Popular
                  </Badge>
                )}
              </div>
              <CardDescription>
                {plan.price === 0 ? (
                  <>
                    <span className="text-2xl font-bold text-foreground">Free</span>
                    <span className="text-xs"> forever</span>
                  </>
                ) : (
                  <>
                    <span className="text-2xl font-bold text-foreground">
                      ₹{(plan.price / 100).toLocaleString("en-IN")}
                    </span>
                    <span className="text-xs">/month</span>
                  </>
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-1.5">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-2 text-xs text-muted-foreground">
                    <Check className="h-3 w-3 text-emerald-500 mt-0.5 shrink-0" />
                    {feature}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <Button
          data-testid="onboarding-wizard-btn-1"
          onClick={() => onSelect(selected)}
          disabled={isLoading}
          className="flex-1"
        >
          {isLoading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <CreditCard className="h-4 w-4 mr-2" />}
          {selected === "free" ? "Start Free" : `Select ${selected.charAt(0).toUpperCase() + selected.slice(1)}`}
        </Button>
        <Button
          data-testid="onboarding-wizard-btn-ghost-2"
          variant="ghost"
          size="sm"
          onClick={onSkip}
          disabled={isLoading}
        >
          <SkipForward className="h-4 w-4 mr-1" /> Skip
        </Button>
      </div>

      {selected !== "free" && (
        <p className="text-xs text-muted-foreground text-center">
          Paid plans include a trial period. You can add payment details anytime from Billing settings.
        </p>
      )}
    </div>
  );
}

function InviteTeamStep({
  onInvite,
  onSkip,
  isLoading,
}: {
  onInvite: (invitations: InvitationEntry[]) => void;
  onSkip: () => void;
  isLoading: boolean;
}) {
  const [entries, setEntries] = useState<InvitationEntry[]>([{ email: "", role: "analyst" }]);

  const addEntry = () => {
    if (entries.length < 20) {
      setEntries([...entries, { email: "", role: "analyst" }]);
    }
  };

  const removeEntry = (index: number) => {
    setEntries(entries.filter((_, i) => i !== index));
  };

  const updateEntry = (index: number, field: keyof InvitationEntry, value: string) => {
    const updated = [...entries];
    updated[index] = { ...updated[index], [field]: value };
    setEntries(updated);
  };

  const validEntries = entries.filter((e) => e.email.trim() && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.email.trim()));
  /* 86.2 — step validation: highlight invalid email entries */
  const invalidEntries = entries.filter((e) => e.email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.email.trim()));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Invite Your Team</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Add team members to collaborate on security operations. You can always add more later.
        </p>
        {/* 86.3 — skip and revisit indicator */}
        <p className="text-xs text-muted-foreground flex items-center gap-1 mt-1">
          <SkipForward className="h-3 w-3" />
          Optional step &mdash; skip now and invite team members later from Team Management
        </p>
      </div>

      <div className="space-y-3">
        {entries.map((entry, index) => (
          <div key={index} className="flex items-center gap-2">
            <Input
              placeholder="colleague@company.com"
              value={entry.email}
              onChange={(e) => updateEntry(index, "email", e.target.value)}
              className={`flex-1 ${entry.email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(entry.email.trim()) ? "border-destructive" : ""}`}
              type="email"
            />
            <select
              value={entry.role}
              onChange={(e) => updateEntry(index, "role", e.target.value)}
              className="h-9 rounded-md border border-input bg-transparent px-2 text-sm min-w-[100px]"
            >
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
            </select>
            {entries.length > 1 && (
              <Button
                data-testid="onboarding-wizard-btn-ghost-3"
                variant="ghost"
                size="icon"
                onClick={() => removeEntry(index)}
                className="shrink-0 h-9 w-9"
              >
                <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
              </Button>
            )}
          </div>
        ))}
      </div>

      {/* 86.2 — validation error for invalid emails */}
      {invalidEntries.length > 0 && (
        <p className="text-xs text-destructive flex items-center gap-1">
          <AlertCircle className="h-3 w-3" />
          {invalidEntries.length} email{invalidEntries.length !== 1 ? "s" : ""} invalid — please fix before sending
        </p>
      )}

      {entries.length < 20 && (
        <Button data-testid="onboarding-wizard-btn-outline-4" variant="outline" size="sm" onClick={addEntry}>
          <Plus className="h-3.5 w-3.5 mr-1" /> Add Another
        </Button>
      )}

      <div className="flex items-center gap-3">
        <Button
          onClick={() => onInvite(validEntries)}
          disabled={isLoading || validEntries.length === 0}
          className="flex-1"
        >
          {isLoading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Users className="h-4 w-4 mr-2" />}
          Send {validEntries.length} Invitation{validEntries.length !== 1 ? "s" : ""}
        </Button>
        <Button variant="ghost" size="sm" onClick={onSkip} disabled={isLoading}>
          <SkipForward className="h-4 w-4 mr-1" /> Skip
        </Button>
      </div>
    </div>
  );
}

function ConnectIntegrationStep({
  onConnect,
  onSkip,
  isLoading,
}: {
  onConnect: () => void;
  onSkip: () => void;
  isLoading: boolean;
}) {
  const [, navigate] = useLocation();
  const [ingestionPath, setIngestionPath] = useState<"connector" | "logs" | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const connectorTypes = [
    { name: "Splunk", category: "SIEM", icon: "S" },
    { name: "CrowdStrike", category: "EDR", icon: "C" },
    { name: "SentinelOne", category: "EDR", icon: "S1" },
    { name: "Microsoft Sentinel", category: "SIEM", icon: "MS" },
    { name: "Slack", category: "Collaboration", icon: "Sl" },
    { name: "PagerDuty", category: "Alerting", icon: "PD" },
    { name: "AWS Security Hub", category: "Cloud", icon: "AWS" },
    { name: "Jira", category: "Ticketing", icon: "J" },
  ];

  const logIngestionOptions = [
    {
      id: "syslog",
      name: "Syslog Forwarding",
      description: "Forward syslog (RFC 5424 / CEF / LEEF) from firewalls, routers, or servers.",
      link: "/log-sources",
    },
    {
      id: "agent",
      name: "Install Lightweight Agent",
      description: "Deploy our native sensor agent on endpoints for real-time log collection.",
      link: "/native-sensors",
    },
    {
      id: "upload",
      name: "Upload Log Files",
      description: "Upload CSV, JSON, or raw log files for one-time or recurring analysis.",
      link: "/log-sources",
    },
    {
      id: "webhook",
      name: "Webhook / HTTP Endpoint",
      description: "Send logs via HTTP POST from any application or script.",
      link: "/log-sources",
    },
  ];

  /* Top-level choice: connector vs log ingestion */
  if (ingestionPath === null) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-semibold">How Would You Like to Get Data In?</h2>
          <p className="text-sm text-muted-foreground mt-1">
            SecureNexus works with any company that has logs. Choose the path that fits your setup.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Card
            data-testid="onboarding-wizard-card-path-connector"
            className="cursor-pointer transition-all hover:shadow-sm hover:border-primary/50 group"
            onClick={() => setIngestionPath("connector")}
          >
            <CardContent className="p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                  <Plug className="h-5 w-5 text-blue-500" />
                </div>
                <div>
                  <p className="text-sm font-semibold">Connect a Security Tool</p>
                  <p className="text-[10px] text-muted-foreground">SIEM, EDR, SOAR, Cloud, Ticketing</p>
                </div>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Already using Splunk, CrowdStrike, Sentinel, or similar? Connect them directly.
              </p>
            </CardContent>
          </Card>

          <Card
            data-testid="onboarding-wizard-card-path-logs"
            className="cursor-pointer transition-all hover:shadow-sm hover:border-primary/50 group"
            onClick={() => setIngestionPath("logs")}
          >
            <CardContent className="p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                  <Scan className="h-5 w-5 text-emerald-500" />
                </div>
                <div>
                  <p className="text-sm font-semibold">Send Logs Directly</p>
                  <p className="text-[10px] text-muted-foreground">Syslog, Agent, Upload, Webhook</p>
                </div>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Forward syslog, install our lightweight agent, upload log files, or push via webhook.
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={onSkip} disabled={isLoading} className="mx-auto">
            <SkipForward className="h-4 w-4 mr-1" /> Skip &mdash; I&rsquo;ll set this up later
          </Button>
        </div>
      </div>
    );
  }

  /* Path B: Log ingestion options */
  if (ingestionPath === "logs") {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => setIngestionPath(null)} className="h-7 px-2">
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <div>
            <h2 className="text-xl font-semibold">Send Logs Directly</h2>
            <p className="text-sm text-muted-foreground mt-0.5">
              Choose how you want to get your logs into SecureNexus.
            </p>
          </div>
        </div>

        <div className="grid gap-3">
          {logIngestionOptions.map((opt) => (
            <Card
              data-testid={`onboarding-wizard-card-log-${opt.id}`}
              key={opt.id}
              className={`cursor-pointer transition-all hover:shadow-sm group ${
                selected === opt.id ? "border-primary ring-2 ring-primary/20" : "hover:border-primary/50"
              }`}
              onClick={() => setSelected(opt.id)}
            >
              <CardContent className="p-4 flex items-center gap-4">
                <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                  <Scan className="h-4.5 w-4.5 text-emerald-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">{opt.name}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{opt.description}</p>
                </div>
                {selected === opt.id && <Check className="h-4 w-4 text-primary shrink-0" />}
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Button
            onClick={() => {
              const opt = logIngestionOptions.find((o) => o.id === selected);
              onConnect();
              if (opt) navigate(opt.link);
            }}
            disabled={isLoading || !selected}
            className="flex-1"
          >
            {isLoading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <PlayCircle className="h-4 w-4 mr-2" />}
            {selected ? `Set Up ${logIngestionOptions.find((o) => o.id === selected)?.name ?? ""}` : "Select an option"}
          </Button>
          <Button variant="ghost" size="sm" onClick={onSkip} disabled={isLoading}>
            <SkipForward className="h-4 w-4 mr-1" /> Skip
          </Button>
        </div>
      </div>
    );
  }

  /* Path A: Connector selection (existing flow) */
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={() => setIngestionPath(null)} className="h-7 px-2">
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <div>
          <h2 className="text-xl font-semibold">Connect a Security Tool</h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            Select a SIEM, EDR, or collaboration tool to start flowing security data into SecureNexus.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {connectorTypes.map((connector) => (
          <Card
            data-testid="onboarding-wizard-card-2"
            key={connector.name}
            className={`cursor-pointer transition-all hover:shadow-sm group ${
              selected === connector.name ? "border-primary ring-2 ring-primary/20" : "hover:border-primary/50"
            }`}
            onClick={() => setSelected(connector.name)}
          >
            <CardContent className="p-3 text-center">
              <div className="w-10 h-10 rounded-lg bg-muted/50 flex items-center justify-center mx-auto mb-2 text-xs font-bold text-muted-foreground group-hover:bg-primary/10 group-hover:text-primary transition-colors">
                {connector.icon}
              </div>
              <p className="text-xs font-medium truncate">{connector.name}</p>
              <p className="text-[10px] text-muted-foreground">{connector.category}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <Button onClick={() => onConnect()} disabled={isLoading || !selected} className="flex-1">
          {isLoading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plug className="h-4 w-4 mr-2" />}
          {selected ? `Connect ${selected}` : "Select an integration"}
        </Button>
        <Button variant="ghost" size="sm" onClick={onSkip} disabled={isLoading}>
          <SkipForward className="h-4 w-4 mr-1" /> Skip
        </Button>
      </div>
    </div>
  );
}

function DashboardTourStep({ onComplete, isLoading }: { onComplete: () => void; isLoading: boolean }) {
  const [currentTourStop, setCurrentTourStop] = useState(0);

  const tourStops = [
    {
      title: "Sidebar Navigation",
      description:
        "Access all platform areas — alerts, incidents, analytics, playbooks, and more. The sidebar collapses for maximum workspace.",
      icon: Navigation,
    },
    {
      title: "Dashboard Metrics",
      description:
        "Real-time overview of your security posture: total alerts, critical issues, open incidents, and resolution rates.",
      icon: BarChart3,
    },
    {
      title: "Alert Trend Chart",
      description:
        "Visualize alert volume over time by severity. Spot spikes early and correlate with incident timelines.",
      icon: Sparkles,
    },
    {
      title: "Command Palette",
      description:
        "Press Cmd+K (or Ctrl+K) to quickly navigate anywhere, search alerts, or run actions without leaving the keyboard.",
      icon: Search,
    },
    {
      title: "Notification Bell",
      description:
        "Real-time alerts and system notifications. Configure channels in Settings to route critical alerts to Slack, PagerDuty, or email.",
      icon: Bell,
    },
    {
      title: "Settings & Configuration",
      description:
        "Manage API keys, integrations, team roles, compliance policies, and organization settings all from one place.",
      icon: Settings,
    },
  ];

  const stop = tourStops[currentTourStop];
  const StopIcon = stop.icon;
  const isLast = currentTourStop === tourStops.length - 1;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Dashboard Tour</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Quick walkthrough of key platform features. You can replay this tour from Settings anytime.
        </p>
      </div>

      <div className="flex items-center gap-2 mb-2">
        {tourStops.map((_, idx) => (
          <button
            key={idx}
            onClick={() => setCurrentTourStop(idx)}
            className={`h-1.5 rounded-full transition-all ${
              idx === currentTourStop
                ? "w-8 bg-primary"
                : idx < currentTourStop
                  ? "w-4 bg-emerald-500/50"
                  : "w-4 bg-muted"
            }`}
          />
        ))}
      </div>

      <Card data-testid="onboarding-wizard-card-3" className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
              <StopIcon className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-base">{stop.title}</h3>
              <p className="text-sm text-muted-foreground mt-1 leading-relaxed">{stop.description}</p>
              <div className="flex items-center gap-2 mt-4">
                {currentTourStop > 0 && (
                  <Button variant="ghost" size="sm" onClick={() => setCurrentTourStop(currentTourStop - 1)}>
                    <ChevronLeft className="h-3.5 w-3.5 mr-1" /> Previous
                  </Button>
                )}
                {!isLast && (
                  <Button size="sm" onClick={() => setCurrentTourStop(currentTourStop + 1)}>
                    Next <ChevronRight className="h-3.5 w-3.5 ml-1" />
                  </Button>
                )}
                {isLast && (
                  <Button size="sm" onClick={onComplete} disabled={isLoading}>
                    {isLoading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Check className="h-4 w-4 mr-2" />}
                    Finish Tour
                  </Button>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <p className="text-xs text-muted-foreground text-center">
        Step {currentTourStop + 1} of {tourStops.length}
      </p>
    </div>
  );
}

export default function OnboardingWizardPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const { data: status, isPending: statusPending } = useQuery<WizardStatus>({
    queryKey: ["/api/wizard/status"],
    staleTime: 0,
  });

  const { data: options } = useQuery<WizardOptions>({
    queryKey: ["/api/wizard/options"],
  });

  const [activeStep, setActiveStep] = useState(0);

  /* 86.1 — resume from server-persisted progress on reload */
  useEffect(() => {
    if (status && !status.isComplete) {
      setActiveStep(status.currentStep);
    }
  }, [status]);

  const selectPlanMutation = useMutation({
    mutationFn: async (planId: string) => {
      const res = await apiRequest("POST", "/api/wizard/select-plan", { planId });
      return res.json();
    },
    onSuccess: (data: {
      planId: string;
      requiresPayment?: boolean;
      checkoutUrl?: string;
      trialActivated?: boolean;
      message?: string;
    }) => {
      if (data.requiresPayment && data.checkoutUrl) {
        window.location.href = data.checkoutUrl;
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["/api/wizard/status"] });
      setActiveStep(1);
      if (data.trialActivated) {
        toast({
          title: "Trial activated",
          description: data.message || "You can upgrade to a paid plan anytime from Billing.",
        });
      } else {
        toast({ title: "Plan selected" });
      }
    },
    onError: (err: Error) => {
      toast({ title: "Failed to select plan", description: err.message, variant: "destructive" });
    },
  });

  const inviteTeamMutation = useMutation({
    mutationFn: async (invitations: InvitationEntry[]) => {
      const res = await apiRequest("POST", "/api/wizard/invite-team", { invitations });
      return res.json();
    },
    onSuccess: (data: { totalInvited: number }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/wizard/status"] });
      setActiveStep(2);
      toast({ title: `${data.totalInvited} invitation${data.totalInvited !== 1 ? "s" : ""} sent` });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to send invitations", description: err.message, variant: "destructive" });
    },
  });

  const connectIntegrationMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/wizard/connect-integration");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/wizard/status"] });
    },
  });

  const skipStepMutation = useMutation({
    mutationFn: async (stepName: string) => {
      const res = await apiRequest("POST", "/api/wizard/skip-step", { stepName });
      return res.json();
    },
    onSuccess: (_data: { nextStep: number }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/wizard/status"] });
      setActiveStep((prev) => prev + 1);
    },
  });

  const completeTourMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/wizard/complete-tour");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/wizard/status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      toast({ title: "Onboarding complete!", description: "Welcome to SecureNexus." });
      navigate("/");
    },
  });

  const completeMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/wizard/complete");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/wizard/status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      navigate("/");
    },
  });

  const handleSkip = useCallback(
    (stepName: string) => {
      skipStepMutation.mutate(stepName);
    },
    [skipStepMutation],
  );

  if (statusPending) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-full max-w-2xl mx-auto p-6 space-y-6">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  }

  if (status?.isComplete) {
    navigate("/");
    return null;
  }

  return (
    <div className="min-h-screen bg-background" data-testid="page-onboarding-wizard">
      <div className="max-w-2xl mx-auto px-4 py-8 md:py-12">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-3">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-lg font-bold">SecureNexus</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Welcome to SecureNexus</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Let's get your security operations platform set up in a few steps.
          </p>
        </div>

        <Card className="mb-6">
          <CardContent className="pt-6">
            <StepProgressBar
              currentStep={activeStep}
              completedSteps={status?.completedSteps ?? []}
              totalSteps={status?.totalSteps ?? STEP_CONFIG.length}
            />
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            {activeStep === 0 && (
              <ChoosePlanStep
                options={options}
                onSelect={(planId) => selectPlanMutation.mutate(planId)}
                onSkip={() => handleSkip("choose_plan")}
                isLoading={selectPlanMutation.isPending}
              />
            )}

            {activeStep === 1 && (
              <InviteTeamStep
                onInvite={(invitations) => inviteTeamMutation.mutate(invitations)}
                onSkip={() => handleSkip("invite_team")}
                isLoading={inviteTeamMutation.isPending}
              />
            )}

            {activeStep === 2 && (
              <ConnectIntegrationStep
                onConnect={() => connectIntegrationMutation.mutate()}
                onSkip={() => handleSkip("connect_integration")}
                isLoading={connectIntegrationMutation.isPending}
              />
            )}

            {activeStep === 3 && (
              <DashboardTourStep
                onComplete={() => completeTourMutation.mutate()}
                isLoading={completeTourMutation.isPending}
              />
            )}

            {activeStep >= 4 && (
              <div className="text-center space-y-4 py-6">
                <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mx-auto">
                  <Check className="h-8 w-8 text-emerald-500" />
                </div>
                <h2 className="text-xl font-semibold">All Set!</h2>
                <p className="text-sm text-muted-foreground">Your workspace is configured and ready to go.</p>

                {/* 86.3 — skipped steps reminder */}
                {(status?.skippedSteps?.length ?? 0) > 0 && (
                  <div className="text-left mx-auto max-w-sm rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                    <p className="text-xs font-medium text-amber-500 flex items-center gap-1 mb-1.5">
                      <Clock className="h-3 w-3" /> Complete Later
                    </p>
                    {status?.skippedSteps?.map((step) => {
                      const cfg = STEP_CONFIG.find((s) => s.key === step);
                      return (
                        <p key={step} className="text-xs text-muted-foreground">
                          &bull; {cfg?.label || step}
                        </p>
                      );
                    })}
                  </div>
                )}

                {/* 86.4 — getting started checklist post-onboarding */}
                <div className="text-left mx-auto max-w-sm rounded-lg border p-3 space-y-2">
                  <p className="text-xs font-medium flex items-center gap-1">
                    <ListChecks className="h-3 w-3 text-primary" /> Getting Started Checklist
                  </p>
                  {[
                    { label: "Set up first connector", done: status?.completedSteps?.includes("connect_integration") },
                    { label: "Configure detection rules", done: false },
                    { label: "Create a playbook", done: false },
                    { label: "Run first scan", done: false },
                  ].map((item) => (
                    <p
                      key={item.label}
                      className={`text-xs flex items-center gap-1.5 ${item.done ? "text-emerald-500" : "text-muted-foreground"}`}
                    >
                      {item.done ? (
                        <Check className="h-3 w-3" />
                      ) : (
                        <span className="h-3 w-3 border rounded-sm inline-block" />
                      )}
                      {item.label}
                    </p>
                  ))}
                </div>

                <Button onClick={() => completeMutation.mutate()} disabled={completeMutation.isPending}>
                  {completeMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <ArrowRight className="h-4 w-4 mr-2" />
                  )}
                  Go to Dashboard
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {activeStep > 0 && activeStep < 5 && (
          <div className="mt-4 text-center">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => completeMutation.mutate()}
              className="text-xs text-muted-foreground underline"
            >
              Skip remaining steps and go to dashboard
            </Button>
          </div>
        )}

        {/* 86.1 — progress persistence indicator */}
        {status?.lastSavedAt && (
          <p className="text-center text-[10px] text-muted-foreground mt-2 flex items-center justify-center gap-1">
            <Save className="h-2.5 w-2.5" />
            Progress auto-saved &middot; Resume anytime
          </p>
        )}

        {/* 86.5 — onboarding analytics indicator */}
        {status?.analytics?.startedAt ? (
          <p className="text-center text-[10px] text-muted-foreground mt-1 flex items-center justify-center gap-1">
            <TrendingUp className="h-2.5 w-2.5" />
            Onboarding started {new Date(status.analytics.startedAt).toLocaleDateString()}
          </p>
        ) : null}

        {/* 86.6 — invited user simplified onboarding indicator */}
        {status?.savedProgress && (status.savedProgress as Record<string, unknown>).isInvitedUser ? (
          <div className="text-center mt-2">
            <Badge variant="outline" className="text-[10px]">
              <UserPlus className="h-2.5 w-2.5 mr-1" />
              Invited Member &mdash; Simplified Setup
            </Badge>
          </div>
        ) : null}
      </div>
    </div>
  );
}
