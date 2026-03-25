import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Brain,
  Shield,
  Gauge,
  RotateCcw,
  Settings2,
  Play,
  Eye,
  Power,
  PowerOff,
  FlaskConical,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Clock,
  ChevronRight,
  Info,
  Lightbulb,
  BarChart3,
  Sliders,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

interface EngineConfig {
  id: string | null;
  orgId: string;
  engineName: string;
  enabled: boolean;
  dryRunMode: boolean;
  policyConfig: Record<string, unknown>;
  lastDryRunAt: string | null;
  lastDryRunResult: Record<string, unknown> | null;
  updatedBy: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface DryRunResult {
  id: string;
  engineName: string;
  status: string;
  simulatedResult: Record<string, unknown> | null;
  durationMs: number | null;
  createdAt: string;
}

interface ExplainLog {
  id: string;
  engineName: string;
  decisionType: string;
  decisionOutcome: string;
  drivers: { factor: string; value: unknown; weight: number }[];
  confidence: number | null;
  createdAt: string;
}

const ENGINE_META: Record<string, { label: string; icon: typeof Brain; description: string; color: string }> = {
  predictive: {
    label: "Predictive Engine",
    icon: Brain,
    description: "Anomaly detection, attack surface mapping, risk forecasting",
    color: "text-violet-400",
  },
  pii: {
    label: "PII Engine",
    icon: Shield,
    description: "Personal data detection and masking across alerts",
    color: "text-emerald-400",
  },
  posture: {
    label: "Posture Engine",
    icon: Gauge,
    description: "Security posture scoring with weighted category analysis",
    color: "text-cyan-400",
  },
  rollback: {
    label: "Rollback Engine",
    icon: RotateCcw,
    description: "Response action reversal and safety controls",
    color: "text-amber-400",
  },
};

const POLICY_FIELDS: Record<
  string,
  {
    key: string;
    label: string;
    type: "slider" | "toggle";
    min?: number;
    max?: number;
    step?: number;
    unit?: string;
    tip?: string;
  }[]
> = {
  predictive: [
    {
      key: "anomalyZScoreThreshold",
      label: "Anomaly Z-Score Threshold",
      type: "slider",
      min: 0.5,
      max: 10,
      step: 0.1,
      tip: "Standard deviations from mean to trigger anomaly. Lower = more sensitive.",
    },
    {
      key: "volumeSpikeMultiplier",
      label: "Volume Spike Multiplier",
      type: "slider",
      min: 1,
      max: 20,
      step: 0.5,
      tip: "Multiplier over baseline to flag volume spikes.",
    },
    {
      key: "severityEscalationMultiplier",
      label: "Severity Escalation Multiplier",
      type: "slider",
      min: 1,
      max: 10,
      step: 0.5,
      tip: "Rate increase in critical alerts to trigger escalation.",
    },
    {
      key: "offHoursRatioThreshold",
      label: "Off-Hours Ratio Threshold",
      type: "slider",
      min: 0.1,
      max: 1,
      step: 0.05,
      unit: "%",
      tip: "Off-hours alert ratio above which to flag.",
    },
    {
      key: "forecastProbabilityThreshold",
      label: "Forecast Probability Threshold",
      type: "slider",
      min: 0.1,
      max: 1,
      step: 0.05,
      unit: "%",
      tip: "Minimum probability to include in risk forecasts.",
    },
    {
      key: "forecastWindowHoursBase",
      label: "Forecast Window (hours)",
      type: "slider",
      min: 1,
      max: 720,
      step: 1,
      tip: "Base prediction window for forecasts.",
    },
  ],
  pii: [
    { key: "maskIps", label: "Mask IP Addresses", type: "toggle", tip: "Redact source/destination IPs in alerts." },
    {
      key: "maskEmails",
      label: "Mask Email Addresses",
      type: "toggle",
      tip: "Redact email addresses found in alert data.",
    },
    { key: "maskHostnames", label: "Mask Hostnames", type: "toggle", tip: "Redact hostnames from alert metadata." },
    { key: "maskUserIds", label: "Mask User IDs", type: "toggle", tip: "Redact user identifiers in alert fields." },
  ],
  posture: [
    {
      key: "cspmWeight",
      label: "CSPM Weight",
      type: "slider",
      min: 0,
      max: 100,
      step: 1,
      unit: "%",
      tip: "Weight of cloud security posture in overall score.",
    },
    {
      key: "endpointWeight",
      label: "Endpoint Weight",
      type: "slider",
      min: 0,
      max: 100,
      step: 1,
      unit: "%",
      tip: "Weight of endpoint health in overall score.",
    },
    {
      key: "incidentWeight",
      label: "Incident Weight",
      type: "slider",
      min: 0,
      max: 100,
      step: 1,
      unit: "%",
      tip: "Weight of incident metrics in overall score.",
    },
    {
      key: "complianceWeight",
      label: "Compliance Weight",
      type: "slider",
      min: 0,
      max: 100,
      step: 1,
      unit: "%",
      tip: "Weight of compliance status in overall score.",
    },
    {
      key: "criticalPenalty",
      label: "Critical Severity Penalty",
      type: "slider",
      min: 0,
      max: 50,
      step: 1,
      tip: "Score penalty per critical finding.",
    },
    {
      key: "highPenalty",
      label: "High Severity Penalty",
      type: "slider",
      min: 0,
      max: 30,
      step: 1,
      tip: "Score penalty per high finding.",
    },
  ],
  rollback: [
    {
      key: "autoRollbackEnabled",
      label: "Auto-Rollback Enabled",
      type: "toggle",
      tip: "Automatically reverse failed response actions.",
    },
    {
      key: "maxRetryAttempts",
      label: "Max Retry Attempts",
      type: "slider",
      min: 1,
      max: 10,
      step: 1,
      tip: "Maximum rollback retry attempts.",
    },
    {
      key: "rollbackTimeoutMinutes",
      label: "Rollback Timeout (min)",
      type: "slider",
      min: 1,
      max: 1440,
      step: 1,
      tip: "Timeout in minutes before rollback is considered failed.",
    },
  ],
};

function PolicyFieldControl({
  field,
  value,
  onChange,
}: {
  field: (typeof POLICY_FIELDS)[string][number];
  value: unknown;
  onChange: (val: unknown) => void;
}) {
  if (field.type === "toggle") {
    return (
      <div className="flex items-center justify-between py-2">
        <div className="flex items-center gap-2">
          <Label className="text-sm">{field.label}</Label>
          {field.tip && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Info className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                </TooltipTrigger>
                <TooltipContent side="right" className="max-w-xs text-xs">
                  {field.tip}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
        <Switch checked={Boolean(value)} onCheckedChange={(v) => onChange(v)} />
      </div>
    );
  }

  const numVal = typeof value === "number" ? value : (field.min ?? 0);
  const displayVal =
    field.unit === "%" ? (field.max === 1 ? `${(numVal * 100).toFixed(0)}%` : `${numVal}%`) : `${numVal}`;

  return (
    <div className="space-y-2 py-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Label className="text-sm">{field.label}</Label>
          {field.tip && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Info className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                </TooltipTrigger>
                <TooltipContent side="right" className="max-w-xs text-xs">
                  {field.tip}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
        <span className="text-sm font-mono tabular-nums text-muted-foreground">{displayVal}</span>
      </div>
      <Slider
        value={[numVal]}
        min={field.min ?? 0}
        max={field.max ?? 100}
        step={field.step ?? 1}
        onValueChange={([v]) => onChange(v)}
        className="cursor-pointer"
      />
      <div className="flex justify-between text-[10px] text-muted-foreground">
        <span>{field.min ?? 0}</span>
        <span>{field.max ?? 100}</span>
      </div>
    </div>
  );
}

function EngineTab({ engineName, config }: { engineName: string; config: EngineConfig }) {
  const { toast } = useToast();
  const meta = ENGINE_META[engineName];
  const Icon = meta.icon;
  const fields = POLICY_FIELDS[engineName] ?? [];
  const [localPolicy, setLocalPolicy] = useState<Record<string, unknown>>(
    (config.policyConfig as Record<string, unknown>) ?? {},
  );
  const [isDirty, setIsDirty] = useState(false);

  const savePolicy = useMutation({
    mutationFn: async (data: { policyConfig: Record<string, unknown> }) => {
      const res = await apiRequest("PUT", `/api/engine-controls/${engineName}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine-controls"] });
      setIsDirty(false);
      toast({ title: "Configuration saved", description: `${meta.label} settings updated.` });
    },
    onError: (error: Error) => {
      toast({ title: "Save failed", description: error.message, variant: "destructive" });
    },
  });

  const toggleEnabled = useMutation({
    mutationFn: async (enabled: boolean) => {
      const res = await apiRequest("PUT", `/api/engine-controls/${engineName}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine-controls"] });
      toast({ title: "Engine updated", description: `${meta.label} ${config.enabled ? "disabled" : "enabled"}.` });
    },
    onError: (error: Error) => {
      toast({ title: "Toggle failed", description: error.message, variant: "destructive" });
    },
  });

  const toggleDryRunMode = useMutation({
    mutationFn: async (dryRunMode: boolean) => {
      const res = await apiRequest("PUT", `/api/engine-controls/${engineName}`, { dryRunMode });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine-controls"] });
      toast({ title: "Dry-run mode updated", description: `${meta.label} dry-run mode toggled.` });
    },
    onError: (error: Error) => {
      toast({ title: "Toggle failed", description: error.message, variant: "destructive" });
    },
  });

  const executeDryRun = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/engine-controls/${engineName}/dry-run`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine-controls"] });
      queryClient.invalidateQueries({ queryKey: [`/api/engine-controls/${engineName}/dry-runs`] });
      queryClient.invalidateQueries({ queryKey: [`/api/engine-controls/${engineName}/explain`] });
      toast({ title: "Dry-run complete", description: `${meta.label} simulation finished.` });
    },
    onError: (error: Error) => {
      toast({ title: "Dry-run failed", description: error.message, variant: "destructive" });
    },
  });

  const { data: dryRuns, isLoading: dryRunsLoading } = useQuery<DryRunResult[]>({
    queryKey: [`/api/engine-controls/${engineName}/dry-runs`],
  });

  const { data: explainLogs, isLoading: explainLoading } = useQuery<ExplainLog[]>({
    queryKey: [`/api/engine-controls/${engineName}/explain`],
  });

  const handlePolicyChange = (key: string, value: unknown) => {
    setLocalPolicy((prev) => ({ ...prev, [key]: value }));
    setIsDirty(true);
  };

  const handleSave = () => {
    savePolicy.mutate({ policyConfig: localPolicy });
  };

  const handleToggleEnabled = () => {
    toggleEnabled.mutate(!config.enabled);
  };

  const handleToggleDryRun = () => {
    toggleDryRunMode.mutate(!config.dryRunMode);
  };

  const totalWeight =
    engineName === "posture"
      ? ((localPolicy.cspmWeight as number) ?? 0) +
        ((localPolicy.endpointWeight as number) ?? 0) +
        ((localPolicy.incidentWeight as number) ?? 0) +
        ((localPolicy.complianceWeight as number) ?? 0)
      : null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg bg-muted/50 border ${meta.color}`}>
            <Icon className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold">{meta.label}</h2>
            <p className="text-xs text-muted-foreground">{meta.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Label className="text-xs text-muted-foreground">Engine</Label>
            <Switch checked={config.enabled} onCheckedChange={handleToggleEnabled} disabled={toggleEnabled.isPending} />
            <Badge variant={config.enabled ? "default" : "secondary"} className="text-[10px]">
              {config.enabled ? (
                <>
                  <Power className="h-3 w-3 mr-1" />
                  Active
                </>
              ) : (
                <>
                  <PowerOff className="h-3 w-3 mr-1" />
                  Disabled
                </>
              )}
            </Badge>
          </div>
          <Separator orientation="vertical" className="h-6" />
          <div className="flex items-center gap-2">
            <Label className="text-xs text-muted-foreground">Dry-Run</Label>
            <Switch
              checked={config.dryRunMode}
              onCheckedChange={handleToggleDryRun}
              disabled={toggleDryRunMode.isPending}
            />
            <Badge variant={config.dryRunMode ? "outline" : "secondary"} className="text-[10px]">
              {config.dryRunMode ? (
                <>
                  <FlaskConical className="h-3 w-3 mr-1" />
                  On
                </>
              ) : (
                "Off"
              )}
            </Badge>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sliders className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm">Policy Tuning</CardTitle>
              </div>
              {isDirty && (
                <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-400/30">
                  Unsaved
                </Badge>
              )}
            </div>
            <CardDescription className="text-xs">Adjust engine thresholds and behavior</CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[420px] pr-3">
              <div className="space-y-1 divide-y divide-border/50">
                {fields.map((field) => (
                  <PolicyFieldControl
                    key={field.key}
                    field={field}
                    value={localPolicy[field.key]}
                    onChange={(v) => handlePolicyChange(field.key, v)}
                  />
                ))}
              </div>
              {totalWeight !== null && (
                <div
                  className={`mt-3 p-2 rounded-md text-xs ${totalWeight === 100 ? "bg-emerald-500/10 text-emerald-400" : "bg-amber-500/10 text-amber-400"}`}
                >
                  Total weight: {totalWeight}% {totalWeight !== 100 && "(should equal 100%)"}
                </div>
              )}
            </ScrollArea>
            <div className="flex gap-2 mt-3 pt-3 border-t">
              <Button size="sm" onClick={handleSave} disabled={!isDirty || savePolicy.isPending} className="flex-1">
                {savePolicy.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                ) : (
                  <Settings2 className="h-3.5 w-3.5 mr-1" />
                )}
                Save Policy
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  executeDryRun.reset();
                  executeDryRun.mutate();
                }}
                disabled={executeDryRun.isPending}
              >
                {executeDryRun.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5 mr-1" />
                )}
                Dry-Run
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <FlaskConical className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">Dry-Run Results</CardTitle>
            </div>
            <CardDescription className="text-xs">Simulated engine outputs without side effects</CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[470px] pr-3">
              {dryRunsLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={i} className="h-20 w-full rounded-lg" />
                  ))}
                </div>
              ) : !dryRuns || dryRuns.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <div className="rounded-full bg-muted p-3 mb-3">
                    <FlaskConical className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <p className="text-sm font-medium">No dry-runs yet</p>
                  <p className="text-xs text-muted-foreground mt-1">Run a simulation to preview engine behavior</p>
                </div>
              ) : (
                <Accordion type="single" collapsible className="space-y-2">
                  {dryRuns.map((run) => (
                    <AccordionItem key={run.id} value={run.id} className="border rounded-lg px-3">
                      <AccordionTrigger className="py-2 hover:no-underline">
                        <div className="flex items-center gap-2 text-left">
                          <Badge
                            variant={
                              run.status === "completed"
                                ? "default"
                                : run.status === "running"
                                  ? "outline"
                                  : "destructive"
                            }
                            className="text-[10px]"
                          >
                            {run.status === "completed" ? (
                              <CheckCircle2 className="h-3 w-3 text-green-500" />
                            ) : run.status === "running" ? (
                              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                            ) : (
                              <AlertTriangle className="h-3 w-3 mr-1" />
                            )}
                            {run.status}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {run.durationMs ? `${run.durationMs}ms` : ""}
                          </span>
                          <span className="text-[10px] text-muted-foreground ml-auto">
                            {run.createdAt ? new Date(run.createdAt).toLocaleString() : ""}
                          </span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent>
                        <pre className="text-[11px] bg-muted/50 rounded-md p-2 overflow-auto max-h-48 whitespace-pre-wrap font-mono">
                          {JSON.stringify(run.simulatedResult, null, 2)}
                        </pre>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              )}
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Eye className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">Explainability</CardTitle>
            </div>
            <CardDescription className="text-xs">Decision drivers and reasoning behind engine outputs</CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[470px] pr-3">
              {explainLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={i} className="h-24 w-full rounded-lg" />
                  ))}
                </div>
              ) : !explainLogs || explainLogs.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <div className="rounded-full bg-muted p-3 mb-3">
                    <Lightbulb className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <p className="text-sm font-medium">No explanations yet</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Run a dry-run or engine execution to generate explainability data
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {explainLogs.map((log) => (
                    <div key={log.id} className="border rounded-lg p-3 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <Badge variant="outline" className="text-[10px]">
                          {log.decisionType}
                        </Badge>
                        {log.confidence !== null && (
                          <span className="text-[10px] text-muted-foreground tabular-nums">
                            {log.confidence}% confidence
                          </span>
                        )}
                      </div>
                      <p className="text-xs font-medium">{log.decisionOutcome}</p>
                      {Array.isArray(log.drivers) && log.drivers.length > 0 && (
                        <div className="space-y-1">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Drivers</p>
                          {log.drivers.map((driver, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between text-[11px] px-2 py-1 bg-muted/30 rounded"
                            >
                              <span className="text-muted-foreground">{driver.factor}</span>
                              <div className="flex items-center gap-2">
                                <span className="font-mono">{String(driver.value)}</span>
                                <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden">
                                  <div
                                    className="h-full bg-cyan-500 rounded-full"
                                    style={{ width: `${(driver.weight ?? 0) * 100}%` }}
                                  />
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                      <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {log.createdAt ? new Date(log.createdAt).toLocaleString() : ""}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function EngineControlsPage() {
  usePageTitle("Engine Controls");
  const [activeTab, setActiveTab] = useState("predictive");

  const {
    data: configs,
    isLoading,
    isError,
    refetch,
  } = useQuery<EngineConfig[]>({
    queryKey: ["/api/engine-controls"],
  });

  const configMap = new Map((configs ?? []).map((c) => [c.engineName, c]));

  const activeEngines = configs?.filter((c) => c.enabled).length ?? 0;
  const dryRunEngines = configs?.filter((c) => c.dryRunMode).length ?? 0;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" aria-label="Engine Controls">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Settings2 className="h-6 w-6 text-primary" aria-hidden="true" />
            <h1 className="text-2xl font-bold tracking-tight">
              <span className="gradient-text-brand">Engine Controls</span>
            </h1>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Tune policies, run simulations, and inspect decision drivers across all security engines
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="relative overflow-visible">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-primary/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Engines</div>
              <Settings2 className="h-3.5 w-3.5 text-primary/60" aria-hidden="true" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums">
              {isLoading ? <Skeleton className="h-7 w-10" /> : 4}
            </div>
          </CardContent>
        </Card>
        <Card className="relative overflow-visible">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-emerald-500/5 to-emerald-500/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Active</div>
              <Power className="h-3.5 w-3.5 text-emerald-500/60" aria-hidden="true" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums text-emerald-400">
              {isLoading ? <Skeleton className="h-7 w-10" /> : activeEngines}
            </div>
          </CardContent>
        </Card>
        <Card className="relative overflow-visible">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-amber-500/5 to-amber-500/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Dry-Run Mode</div>
              <FlaskConical className="h-3.5 w-3.5 text-amber-500/60" aria-hidden="true" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums text-amber-400">
              {isLoading ? <Skeleton className="h-7 w-10" /> : dryRunEngines}
            </div>
          </CardContent>
        </Card>
        <Card className="relative overflow-visible">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-cyan-500/5 to-cyan-500/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Coverage</div>
              <BarChart3 className="h-3.5 w-3.5 text-cyan-500/60" aria-hidden="true" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums text-cyan-400">
              {isLoading ? <Skeleton className="h-7 w-10" /> : `${Math.round((activeEngines / 4) * 100)}%`}
            </div>
          </CardContent>
        </Card>
      </div>

      {isError ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
              <AlertTriangle className="h-6 w-6 text-destructive" />
            </div>
            <p className="text-sm font-medium">Failed to load engine configurations</p>
            <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
              Try Again
            </Button>
          </CardContent>
        </Card>
      ) : isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-10 w-full rounded-lg" />
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Skeleton className="h-[520px] rounded-lg" />
            <Skeleton className="h-[520px] rounded-lg" />
            <Skeleton className="h-[520px] rounded-lg" />
          </div>
        </div>
      ) : (
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-4">
            {(["predictive", "pii", "posture", "rollback"] as const).map((name) => {
              const meta = ENGINE_META[name];
              const IconComp = meta.icon;
              const cfg = configMap.get(name);
              return (
                <TabsTrigger key={name} value={name} className="flex items-center gap-1.5 text-xs">
                  <IconComp className={`h-3.5 w-3.5 ${meta.color}`} />
                  <span className="hidden sm:inline">{meta.label.replace(" Engine", "")}</span>
                  {cfg && !cfg.enabled && (
                    <Badge variant="secondary" className="text-[9px] px-1 py-0 h-3.5 ml-1">
                      Off
                    </Badge>
                  )}
                  {cfg?.dryRunMode && (
                    <Badge
                      variant="outline"
                      className="text-[9px] px-1 py-0 h-3.5 ml-1 text-amber-400 border-amber-400/30"
                    >
                      Dry
                    </Badge>
                  )}
                </TabsTrigger>
              );
            })}
          </TabsList>
          {(["predictive", "pii", "posture", "rollback"] as const).map((name) => {
            const cfg = configMap.get(name);
            const defaultConfig: EngineConfig = {
              id: null,
              orgId: "",
              engineName: name,
              enabled: true,
              dryRunMode: false,
              policyConfig: {},
              lastDryRunAt: null,
              lastDryRunResult: null,
              updatedBy: null,
              createdAt: null,
              updatedAt: null,
            };
            return (
              <TabsContent key={name} value={name} className="mt-4">
                <EngineTab engineName={name} config={cfg ?? defaultConfig} />
              </TabsContent>
            );
          })}
        </Tabs>
      )}
    </div>
  );
}
