import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Brain,
  Shield,
  Gauge,
  RotateCcw,
  Play,
  FlaskConical,
  Info,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  SquareSlash,
  Settings2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from "@/components/ui/collapsible";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";

// ─── Types ────────────────────────────────────────────────────────────────────

interface EngineLastRun {
  at: string;
  durationMs: number;
  summary: Record<string, unknown>;
}

interface EngineStatus {
  enabled: boolean;
  lastRun: EngineLastRun | null;
  description: string;
  capabilities: string[];
  latestScore?: Record<string, number> | null;
  pendingRollbacks?: number;
}

interface EnginesStatus {
  predictive: EngineStatus;
  pii: EngineStatus;
  posture: EngineStatus;
  rollback: EngineStatus;
}

interface PredictivePolicy {
  enabled: boolean;
  zScoreThreshold: number;
  minAlertsForAnomaly: number;
  criticalMultiplier: number;
  offHoursStart: number;
  offHoursEnd: number;
  offHoursRatioMultiplier: number;
}

interface PiiPolicy {
  enabled: boolean;
  maskSourceIp: boolean;
  maskDestIp: boolean;
  maskUserId: boolean;
  maskHostname: boolean;
  maskEmailsInText: boolean;
  maskIpsInText: boolean;
}

interface PosturePolicy {
  enabled: boolean;
  cspmWeight: number;
  endpointWeight: number;
  incidentWeight: number;
  complianceWeight: number;
  criticalFindingPenalty: number;
  highFindingPenalty: number;
  mediumFindingPenalty: number;
  lowFindingPenalty: number;
  criticalIncidentPenalty: number;
  highIncidentPenalty: number;
  mediumIncidentPenalty: number;
  lowIncidentPenalty: number;
}

interface RollbackPolicy {
  enabled: boolean;
  requireConfirmation: boolean;
  allowedActions: string[];
}

interface AllPolicies {
  predictive: PredictivePolicy;
  pii: PiiPolicy;
  posture: PosturePolicy;
  rollback: RollbackPolicy;
  defaults: {
    predictive: PredictivePolicy;
    pii: PiiPolicy;
    posture: PosturePolicy;
    rollback: RollbackPolicy;
  };
}

interface ExplainStep {
  step: number;
  name: string;
  rationale: string;
}

interface ExplainResult {
  engine: string;
  title: string;
  description: string;
  howItWorks: ExplainStep[];
  thresholds?: Record<string, { current: unknown; default?: unknown; description: string }>;
  weights?: Record<string, { weight?: number; percentage?: string }>;
  enabledMasks?: Record<string, boolean>;
  reversibleActions?: { forward: string; inverse: string; allowed: boolean }[];
}

// ─── Metadata ─────────────────────────────────────────────────────────────────

const ENGINE_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  predictive: { label: "Predictive Engine", icon: Brain, color: "text-purple-400" },
  pii: { label: "PII Engine", icon: Shield, color: "text-blue-400" },
  posture: { label: "Posture Engine", icon: Gauge, color: "text-green-400" },
  rollback: { label: "Rollback Engine", icon: RotateCcw, color: "text-orange-400" },
};

const ROLLBACK_ACTIONS: Record<string, string> = {
  isolate_host: "unisolate_host",
  block_ip: "unblock_ip",
  block_domain: "unblock_domain",
  quarantine_file: "restore_file",
  disable_user: "enable_user",
  kill_process: "restart_process",
};

// ─── Small helpers ────────────────────────────────────────────────────────────

function StatusDot({ enabled }: { enabled: boolean }) {
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${enabled ? "bg-green-500" : "bg-zinc-500"}`}
      aria-label={enabled ? "Enabled" : "Disabled"}
    />
  );
}

function LastRunLabel({ lastRun }: { lastRun: EngineLastRun | null }) {
  if (!lastRun) return <span className="text-xs text-muted-foreground">Never run</span>;
  const ago = Math.round((Date.now() - new Date(lastRun.at).getTime()) / 1000);
  const label =
    ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.round(ago / 60)}m ago` : `${Math.round(ago / 3600)}h ago`;
  return (
    <span className="text-xs text-muted-foreground">
      Last run: {label} ({lastRun.durationMs}ms)
    </span>
  );
}

function DryRunResult({ result }: { result: Record<string, unknown> | null }) {
  if (!result) return null;
  return (
    <ScrollArea className="max-h-64 rounded border border-border bg-muted/30 p-3 mt-3">
      <pre className="text-xs font-mono whitespace-pre-wrap text-muted-foreground">
        {JSON.stringify(result, null, 2)}
      </pre>
    </ScrollArea>
  );
}

// ─── Policy panels ────────────────────────────────────────────────────────────

function PredictivePolicyPanel({
  policy,
  defaults,
  onChange,
}: {
  policy: PredictivePolicy;
  defaults: PredictivePolicy;
  onChange: (u: Partial<PredictivePolicy>) => void;
}) {
  return (
    <div className="space-y-5">
      <div>
        <Label className="text-sm font-medium">
          Z-Score Threshold:{" "}
          <span className="text-primary font-mono">{policy.zScoreThreshold.toFixed(1)}</span>
          <span className="text-xs text-muted-foreground ml-2">(default: {defaults.zScoreThreshold})</span>
        </Label>
        <p className="text-xs text-muted-foreground mb-2">
          Minimum z-score to flag a volume spike. Lower = more sensitive.
        </p>
        <Slider
          min={1} max={6} step={0.1}
          value={[policy.zScoreThreshold]}
          onValueChange={([v]) => onChange({ zScoreThreshold: v })}
          aria-label="Z-Score threshold"
        />
        <div className="flex justify-between text-xs text-muted-foreground mt-1">
          <span>1.0 (sensitive)</span><span>6.0 (strict)</span>
        </div>
      </div>

      <div>
        <Label className="text-sm font-medium">
          Min Alerts for Anomaly:{" "}
          <span className="text-primary font-mono">{policy.minAlertsForAnomaly}</span>
          <span className="text-xs text-muted-foreground ml-2">(default: {defaults.minAlertsForAnomaly})</span>
        </Label>
        <p className="text-xs text-muted-foreground mb-2">
          Minimum alert count to generate an anomaly (suppresses single-alert noise).
        </p>
        <Slider
          min={1} max={20} step={1}
          value={[policy.minAlertsForAnomaly]}
          onValueChange={([v]) => onChange({ minAlertsForAnomaly: v })}
        />
        <div className="flex justify-between text-xs text-muted-foreground mt-1">
          <span>1</span><span>20</span>
        </div>
      </div>

      <div>
        <Label className="text-sm font-medium">
          Critical Alert Multiplier:{" "}
          <span className="text-primary font-mono">{policy.criticalMultiplier}×</span>
          <span className="text-xs text-muted-foreground ml-2">(default: {defaults.criticalMultiplier})</span>
        </Label>
        <p className="text-xs text-muted-foreground mb-2">
          Critical alerts must be this many times above daily baseline to trigger severity escalation.
        </p>
        <Slider
          min={1.5} max={5} step={0.5}
          value={[policy.criticalMultiplier]}
          onValueChange={([v]) => onChange({ criticalMultiplier: v })}
        />
        <div className="flex justify-between text-xs text-muted-foreground mt-1">
          <span>1.5× (sensitive)</span><span>5× (strict)</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">
            Off-Hours Start (UTC): <span className="text-primary font-mono">{policy.offHoursStart}:00</span>
          </Label>
          <Slider
            min={0} max={12} step={1}
            value={[policy.offHoursStart]}
            onValueChange={([v]) => onChange({ offHoursStart: v })}
            className="mt-2"
          />
        </div>
        <div>
          <Label className="text-sm font-medium">
            Off-Hours End (UTC): <span className="text-primary font-mono">{policy.offHoursEnd}:00</span>
          </Label>
          <Slider
            min={1} max={12} step={1}
            value={[policy.offHoursEnd]}
            onValueChange={([v]) => onChange({ offHoursEnd: v })}
            className="mt-2"
          />
        </div>
      </div>

      <div>
        <Label className="text-sm font-medium">
          Off-Hours Ratio Multiplier:{" "}
          <span className="text-primary font-mono">{policy.offHoursRatioMultiplier}×</span>
          <span className="text-xs text-muted-foreground ml-2">(default: {defaults.offHoursRatioMultiplier})</span>
        </Label>
        <p className="text-xs text-muted-foreground mb-2">
          Off-hours ratio must exceed baseline by this factor to flag a timing anomaly.
        </p>
        <Slider
          min={1.5} max={5} step={0.5}
          value={[policy.offHoursRatioMultiplier]}
          onValueChange={([v]) => onChange({ offHoursRatioMultiplier: v })}
        />
      </div>
    </div>
  );
}

function PiiPolicyPanel({
  policy,
  onChange,
}: {
  policy: PiiPolicy;
  onChange: (u: Partial<PiiPolicy>) => void;
}) {
  const toggles: { key: keyof PiiPolicy; label: string; description: string }[] = [
    { key: "maskSourceIp", label: "Mask Source IP", description: "e.g. 10.0.1.42 → 10.0.1.***" },
    { key: "maskDestIp", label: "Mask Destination IP", description: "e.g. 192.168.1.5 → 192.168.1.***" },
    { key: "maskUserId", label: "Mask User ID", description: "e.g. jdoe@corp.com → user_***corp" },
    { key: "maskHostname", label: "Mask Hostname", description: "e.g. server-01 → ser***" },
    { key: "maskEmailsInText", label: "Mask Emails in Text Fields", description: "Scans description & analystNotes for email patterns" },
    { key: "maskIpsInText", label: "Mask IPs in Text Fields", description: "Scans description & analystNotes for IP patterns" },
  ];

  return (
    <div className="space-y-1">
      {toggles.map(({ key, label, description }) => (
        <div
          key={key}
          className="flex items-center justify-between gap-3 py-2.5 border-b border-border/40 last:border-0"
        >
          <div>
            <div className="text-sm font-medium">{label}</div>
            <div className="text-xs text-muted-foreground">{description}</div>
          </div>
          <Switch
            checked={policy[key] as boolean}
            onCheckedChange={(v) => onChange({ [key]: v })}
            aria-label={label}
          />
        </div>
      ))}
    </div>
  );
}

function PosturePolicyPanel({
  policy,
  defaults,
  onChange,
}: {
  policy: PosturePolicy;
  defaults: PosturePolicy;
  onChange: (u: Partial<PosturePolicy>) => void;
}) {
  const weightSum =
    policy.cspmWeight + policy.endpointWeight + policy.incidentWeight + policy.complianceWeight;
  const weightOk = Math.abs(weightSum - 1.0) < 0.011;

  return (
    <div className="space-y-5">
      <div>
        <div className="flex items-center gap-2 mb-3">
          <span className="text-sm font-semibold">Score Weights</span>
          <Badge variant={weightOk ? "default" : "destructive"} className="text-xs">
            Sum: {weightSum.toFixed(2)} {weightOk ? "✓" : "— must equal 1.00"}
          </Badge>
        </div>
        {(["cspm", "endpoint", "incident", "compliance"] as const).map((key) => {
          const pk = `${key}Weight` as keyof PosturePolicy;
          const labelMap = { cspm: "CSPM", endpoint: "Endpoint", incident: "Incident", compliance: "Compliance" };
          return (
            <div key={key} className="mb-4">
              <Label className="text-xs font-medium">
                {labelMap[key]} Weight:{" "}
                <span className="text-primary font-mono">
                  {((policy[pk] as number) * 100).toFixed(0)}%
                </span>
              </Label>
              <Slider
                min={0.05} max={0.6} step={0.05}
                value={[policy[pk] as number]}
                onValueChange={([v]) => onChange({ [pk]: v })}
                className="mt-1"
                aria-label={`${labelMap[key]} weight`}
              />
            </div>
          );
        })}
      </div>

      <Separator />

      <div>
        <div className="text-sm font-semibold mb-3">CSPM Finding Penalties (points deducted)</div>
        <div className="grid grid-cols-2 gap-3">
          {(["critical", "high", "medium", "low"] as const).map((sev) => {
            const pk = `${sev}FindingPenalty` as keyof PosturePolicy;
            const colors: Record<string, string> = {
              critical: "text-red-400", high: "text-orange-400",
              medium: "text-yellow-400", low: "text-blue-400",
            };
            return (
              <div key={sev}>
                <Label className={`text-xs font-medium capitalize ${colors[sev]}`}>
                  {sev}:{" "}
                  <span className="text-primary font-mono">{policy[pk]}</span> pts
                  <span className="text-muted-foreground ml-1">(default: {defaults[pk]})</span>
                </Label>
                <Slider
                  min={0} max={25} step={1}
                  value={[policy[pk] as number]}
                  onValueChange={([v]) => onChange({ [pk]: v })}
                  className="mt-1"
                />
              </div>
            );
          })}
        </div>
      </div>

      <Separator />

      <div>
        <div className="text-sm font-semibold mb-3">Incident Penalties — last 30 days</div>
        <div className="grid grid-cols-2 gap-3">
          {(["critical", "high", "medium", "low"] as const).map((sev) => {
            const pk = `${sev}IncidentPenalty` as keyof PosturePolicy;
            const colors: Record<string, string> = {
              critical: "text-red-400", high: "text-orange-400",
              medium: "text-yellow-400", low: "text-blue-400",
            };
            return (
              <div key={sev}>
                <Label className={`text-xs font-medium capitalize ${colors[sev]}`}>
                  {sev}:{" "}
                  <span className="text-primary font-mono">{policy[pk]}</span> pts
                  <span className="text-muted-foreground ml-1">(default: {defaults[pk]})</span>
                </Label>
                <Slider
                  min={0} max={30} step={1}
                  value={[policy[pk] as number]}
                  onValueChange={([v]) => onChange({ [pk]: v })}
                  className="mt-1"
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function RollbackPolicyPanel({
  policy,
  onChange,
}: {
  policy: RollbackPolicy;
  onChange: (u: Partial<RollbackPolicy>) => void;
}) {
  const allActions = Object.keys(ROLLBACK_ACTIONS);

  const toggleAction = (action: string, enabled: boolean) => {
    const next = enabled
      ? [...policy.allowedActions, action]
      : policy.allowedActions.filter((a) => a !== action);
    onChange({ allowedActions: next });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium">Require Confirmation</div>
          <div className="text-xs text-muted-foreground">
            Show a confirmation dialog before executing any rollback
          </div>
        </div>
        <Switch
          checked={policy.requireConfirmation}
          onCheckedChange={(v) => onChange({ requireConfirmation: v })}
          aria-label="Require confirmation"
        />
      </div>

      <Separator />

      <div>
        <div className="text-sm font-semibold mb-1">Allowed Rollback Actions</div>
        <p className="text-xs text-muted-foreground mb-3">
          Disable an action type to block its rollback from executing even if a rollback record exists.
        </p>
        <div className="space-y-2">
          {allActions.map((action) => (
            <div
              key={action}
              className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0"
            >
              <div>
                <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{action}</code>
                <span className="text-xs text-muted-foreground ml-2">→ {ROLLBACK_ACTIONS[action]}</span>
              </div>
              <Switch
                checked={policy.allowedActions.includes(action)}
                onCheckedChange={(v) => toggleAction(action, v)}
                aria-label={`Allow rollback of ${action}`}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Explainability dialog ────────────────────────────────────────────────────

function ExplainDialog({
  engine,
  open,
  onClose,
}: {
  engine: string | null;
  open: boolean;
  onClose: () => void;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);

  const { data: explain, isLoading } = useQuery<ExplainResult>({
    queryKey: ["/api/engine-controls/explain", engine],
    queryFn: () =>
      apiRequest("GET", `/api/engine-controls/explain/${engine}`).then((r) => r.json()),
    enabled: open && !!engine,
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Info className="h-4 w-4 text-blue-400" />
            {explain?.title ?? "Engine Explainability"}
          </DialogTitle>
          <DialogDescription>{explain?.description}</DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : explain ? (
          <div className="space-y-5">
            <div>
              <h4 className="text-sm font-semibold mb-2">How It Works</h4>
              <div className="space-y-1">
                {explain.howItWorks.map((step) => (
                  <Collapsible
                    key={step.step}
                    open={expanded === step.step}
                    onOpenChange={(o) => setExpanded(o ? step.step : null)}
                  >
                    <CollapsibleTrigger className="flex items-center gap-2 w-full text-left py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                      <span className="text-xs font-mono bg-primary/20 text-primary px-1.5 py-0.5 rounded w-5 text-center shrink-0">
                        {step.step}
                      </span>
                      <span className="text-sm font-medium flex-1">{step.name}</span>
                      {expanded === step.step ? (
                        <ChevronDown className="h-3 w-3 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-3 w-3 text-muted-foreground" />
                      )}
                    </CollapsibleTrigger>
                    <CollapsibleContent className="px-4 pb-3">
                      <p className="text-xs text-muted-foreground leading-relaxed">{step.rationale}</p>
                    </CollapsibleContent>
                  </Collapsible>
                ))}
              </div>
            </div>

            {explain.thresholds && (
              <div>
                <h4 className="text-sm font-semibold mb-2">Active Thresholds</h4>
                <div className="space-y-2">
                  {Object.entries(explain.thresholds).map(([key, val]) => (
                    <div
                      key={key}
                      className="flex items-start justify-between gap-2 text-xs py-1.5 border-b border-border/30 last:border-0"
                    >
                      <div>
                        <code className="bg-muted px-1 py-0.5 rounded">{key}</code>
                        <p className="text-muted-foreground mt-0.5">{val.description}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="font-mono text-primary">{String(val.current)}</span>
                        {val.default !== undefined && (
                          <p className="text-muted-foreground">default: {String(val.default)}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {explain.weights && (
              <div>
                <h4 className="text-sm font-semibold mb-2">Score Weights</h4>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(explain.weights)
                    .filter(([k]) => k !== "total")
                    .map(([key, val]) => (
                      <div key={key} className="bg-muted/30 rounded-md p-2 text-center">
                        <div className="text-xs font-medium capitalize">{key}</div>
                        <div className="text-xl font-bold text-primary">
                          {val.percentage ?? `${((val.weight ?? 0) * 100).toFixed(0)}%`}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {explain.enabledMasks && (
              <div>
                <h4 className="text-sm font-semibold mb-2">Active Masking Rules</h4>
                <div className="grid grid-cols-2 gap-1">
                  {Object.entries(explain.enabledMasks).map(([key, enabled]) => (
                    <div key={key} className="flex items-center gap-2 text-xs py-0.5">
                      {enabled ? (
                        <CheckCircle2 className="h-3 w-3 text-green-400 shrink-0" />
                      ) : (
                        <XCircle className="h-3 w-3 text-zinc-500 shrink-0" />
                      )}
                      <span className={enabled ? "" : "text-muted-foreground"}>{key}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {explain.reversibleActions && (
              <div>
                <h4 className="text-sm font-semibold mb-2">Reversible Action Map</h4>
                <div className="space-y-1">
                  {explain.reversibleActions.map((a) => (
                    <div key={a.forward} className="flex items-center gap-2 text-xs py-1">
                      <code className="bg-muted px-1.5 py-0.5 rounded">{a.forward}</code>
                      <span className="text-muted-foreground">→</span>
                      <code className="bg-muted px-1.5 py-0.5 rounded">{a.inverse}</code>
                      {a.allowed ? (
                        <CheckCircle2 className="h-3 w-3 text-green-400 ml-auto" />
                      ) : (
                        <XCircle className="h-3 w-3 text-red-400 ml-auto" />
                      )}
                      <span className={a.allowed ? "text-green-400" : "text-red-400"}>
                        {a.allowed ? "Allowed" : "Blocked"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        <DialogFooter>
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function EngineControlsPage() {
  const { toast } = useToast();
  const [activeEngine, setActiveEngine] = useState<string>("predictive");
  const [dryRunResults, setDryRunResults] = useState<Record<string, Record<string, unknown> | null>>({
    predictive: null,
    pii: null,
    posture: null,
    rollback: null,
  });
  const [explainEngine, setExplainEngine] = useState<string | null>(null);
  const [localPolicies, setLocalPolicies] = useState<Record<string, Record<string, unknown>>>({});
  const [pendingChanges, setPendingChanges] = useState<Set<string>>(new Set());

  // ── Queries ─────────────────────────────────────────────────────────────
  const { data: status, isLoading: statusLoading, refetch: refetchStatus } = useQuery<EnginesStatus>({
    queryKey: ["/api/engine-controls/status"],
    queryFn: () => apiRequest("GET", "/api/engine-controls/status").then((r) => r.json()),
    refetchInterval: 30_000,
  });

  const { data: policies, isLoading: policiesLoading, refetch: refetchPolicies } = useQuery<AllPolicies>({
    queryKey: ["/api/engine-controls/policy"],
    queryFn: () => apiRequest("GET", "/api/engine-controls/policy").then((r) => r.json()),
  });

  // ── Mutations ────────────────────────────────────────────────────────────
  const savePolicyMutation = useMutation({
    mutationFn: ({ engine, policy }: { engine: string; policy: Record<string, unknown> }) =>
      apiRequest("PUT", "/api/engine-controls/policy", { engine, policy }).then((r) => r.json()),
    onSuccess: (_data, { engine }) => {
      toast({ title: "Policy saved", description: `${ENGINE_META[engine]?.label} policy updated.` });
      refetchPolicies();
      refetchStatus();
      setPendingChanges((prev) => {
        const n = new Set(prev);
        n.delete(engine);
        return n;
      });
    },
    onError: (err: any) => {
      toast({ title: "Save failed", description: err?.message ?? "Could not save policy.", variant: "destructive" });
    },
  });

  const resetPolicyMutation = useMutation({
    mutationFn: (engine: string) =>
      apiRequest("POST", "/api/engine-controls/policy/reset", { engine }).then((r) => r.json()),
    onSuccess: (_data, engine) => {
      toast({ title: "Policy reset", description: `${ENGINE_META[engine]?.label} restored to defaults.` });
      refetchPolicies();
      setLocalPolicies((prev) => {
        const n = { ...prev };
        delete n[engine];
        return n;
      });
      setPendingChanges((prev) => {
        const n = new Set(prev);
        n.delete(engine);
        return n;
      });
    },
  });

  const dryRunMutation = useMutation({
    mutationFn: (engine: string) =>
      apiRequest("POST", `/api/engine-controls/dry-run/${engine}`, {}).then((r) => r.json()),
    onSuccess: (data: Record<string, unknown>, engine) => {
      setDryRunResults((prev) => ({ ...prev, [engine]: data }));
      toast({ title: "Dry-run complete", description: `${ENGINE_META[engine]?.label} dry-run finished.` });
    },
    onError: (err: any, engine) => {
      toast({ title: "Dry-run failed", description: err?.message ?? "Error", variant: "destructive" });
      setDryRunResults((prev) => ({ ...prev, [engine]: null }));
    },
  });

  const runMutation = useMutation({
    mutationFn: (engine: string) =>
      apiRequest("POST", `/api/engine-controls/run/${engine}`, {}).then((r) => r.json()),
    onSuccess: (_data, engine) => {
      toast({ title: "Engine triggered", description: `${ENGINE_META[engine]?.label} run complete.` });
      refetchStatus();
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/posture"] });
    },
    onError: (err: any) => {
      toast({ title: "Run failed", description: err?.message ?? "Error", variant: "destructive" });
    },
  });

  // ── Policy helpers ───────────────────────────────────────────────────────
  function getEffectivePolicy(engine: string): Record<string, unknown> {
    const base = (policies?.[engine as keyof AllPolicies] ?? {}) as Record<string, unknown>;
    const local = localPolicies[engine] ?? {};
    return { ...base, ...local };
  }

  function updateLocalPolicy(engine: string, updates: Record<string, unknown>) {
    setLocalPolicies((prev) => ({ ...prev, [engine]: { ...prev[engine], ...updates } }));
    setPendingChanges((prev) => new Set([...prev, engine]));
  }

  function saveEnginePolicy(engine: string) {
    savePolicyMutation.mutate({ engine, policy: getEffectivePolicy(engine) });
  }

  function toggleEngine(engine: string, enabled: boolean) {
    savePolicyMutation.mutate({ engine, policy: { ...getEffectivePolicy(engine), enabled } });
  }

  // ─────────────────────────────────────────────────────────────────────────
  const engines = ["predictive", "pii", "posture", "rollback"] as const;
  const loading = statusLoading || policiesLoading;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Settings2 className="h-6 w-6 text-primary" />
            Engine Controls
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Tune policy thresholds, validate with dry-runs, and understand how each engine makes decisions.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => { refetchStatus(); refetchPolicies(); }}
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4 mr-1" /> Refresh
        </Button>
      </div>

      {/* Status overview */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {engines.map((eng) => {
          const meta = ENGINE_META[eng];
          const Icon = meta.icon;
          const s = status?.[eng];
          return (
            <button
              key={eng}
              onClick={() => setActiveEngine(eng)}
              className={`text-left rounded-lg border p-3 transition-all focus:outline-none focus:ring-2 focus:ring-primary/40 ${
                activeEngine === eng
                  ? "border-primary/50 bg-primary/5"
                  : "border-border/50 hover:border-border"
              }`}
              aria-pressed={activeEngine === eng}
            >
              <div className="flex items-center gap-2 mb-1">
                <Icon className={`h-4 w-4 ${meta.color}`} />
                <StatusDot enabled={s?.enabled ?? false} />
                {pendingChanges.has(eng) && (
                  <span className="text-xs text-yellow-400 ml-auto">unsaved</span>
                )}
              </div>
              <div className="text-xs font-semibold">{meta.label}</div>
              <LastRunLabel lastRun={s?.lastRun ?? null} />
              {eng === "posture" && s?.latestScore && (
                <div className="text-xl font-bold text-primary mt-1">
                  {s.latestScore.overall}
                </div>
              )}
              {eng === "rollback" && (s?.pendingRollbacks ?? 0) > 0 && (
                <div className="text-xs text-orange-400 mt-1">
                  {s!.pendingRollbacks} pending
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Detail panels */}
      <Tabs value={activeEngine} onValueChange={setActiveEngine}>
        <TabsList className="grid w-full grid-cols-4">
          {engines.map((eng) => {
            const meta = ENGINE_META[eng];
            const Icon = meta.icon;
            return (
              <TabsTrigger key={eng} value={eng} className="flex items-center gap-1.5">
                <Icon className={`h-3.5 w-3.5 ${meta.color}`} />
                <span className="hidden sm:inline">{meta.label.split(" ")[0]}</span>
              </TabsTrigger>
            );
          })}
        </TabsList>

        {engines.map((eng) => {
          const meta = ENGINE_META[eng];
          const Icon = meta.icon;
          const s = status?.[eng];
          const effective = getEffectivePolicy(eng);
          const hasPending = pendingChanges.has(eng);
          const dryResult = dryRunResults[eng];
          const isDryRunning = dryRunMutation.isPending && (dryRunMutation.variables as string) === eng;
          const isRunning = runMutation.isPending && (runMutation.variables as string) === eng;

          return (
            <TabsContent key={eng} value={eng} className="space-y-4 mt-4">
              {/* Engine card */}
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-muted/50">
                        <Icon className={`h-5 w-5 ${meta.color}`} />
                      </div>
                      <div>
                        <CardTitle className="text-base">{meta.label}</CardTitle>
                        <CardDescription className="text-xs mt-0.5">
                          {s?.description}
                        </CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Switch
                        checked={(effective.enabled as boolean) ?? true}
                        onCheckedChange={(v) => toggleEngine(eng, v)}
                        aria-label={`${meta.label} enabled`}
                      />
                      <span className="text-xs text-muted-foreground">
                        {effective.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </div>
                  </div>

                  {s?.capabilities && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {s.capabilities.map((cap) => (
                        <Badge key={cap} variant="secondary" className="text-xs">
                          {cap.replace(/_/g, " ")}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardHeader>

                <CardContent className="pt-0 space-y-3">
                  <div className="flex gap-2 flex-wrap">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => dryRunMutation.mutate(eng)}
                      disabled={isDryRunning}
                      aria-label={`Dry-run ${meta.label}`}
                    >
                      {isDryRunning ? (
                        <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                      ) : (
                        <FlaskConical className="h-3.5 w-3.5 mr-1" />
                      )}
                      Dry-run
                    </Button>

                    <Button
                      size="sm"
                      onClick={() => runMutation.mutate(eng)}
                      disabled={isRunning || !effective.enabled}
                      aria-label={`Run ${meta.label}`}
                    >
                      {isRunning ? (
                        <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                      ) : (
                        <Play className="h-3.5 w-3.5 mr-1" />
                      )}
                      Run Now
                    </Button>

                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setExplainEngine(eng)}
                      aria-label={`Explain ${meta.label}`}
                    >
                      <Info className="h-3.5 w-3.5 mr-1" /> Explain
                    </Button>
                  </div>

                  {dryResult && (
                    <div>
                      <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-1">
                        <FlaskConical className="h-3.5 w-3.5" /> Dry-run result
                        {(dryResult as any).skipped && (
                          <Badge variant="secondary" className="ml-1 text-xs">
                            <SquareSlash className="h-3 w-3 mr-1" />
                            Skipped — engine disabled
                          </Badge>
                        )}
                      </div>
                      <DryRunResult result={dryResult} />
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Policy tuning card */}
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Settings2 className="h-4 w-4 text-muted-foreground" />
                      Policy Tuning
                      {hasPending && (
                        <Badge
                          variant="outline"
                          className="text-yellow-400 border-yellow-400/40 text-xs"
                        >
                          Unsaved changes
                        </Badge>
                      )}
                    </CardTitle>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => resetPolicyMutation.mutate(eng)}
                        disabled={resetPolicyMutation.isPending}
                        aria-label="Reset to defaults"
                      >
                        <RotateCcw className="h-3.5 w-3.5 mr-1" /> Reset
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => saveEnginePolicy(eng)}
                        disabled={!hasPending || savePolicyMutation.isPending}
                        aria-label="Save policy"
                      >
                        {savePolicyMutation.isPending && (
                          <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                        )}
                        Save
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                <CardContent>
                  {loading ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" /> Loading policies…
                    </div>
                  ) : (
                    <>
                      {eng === "predictive" && policies && (
                        <PredictivePolicyPanel
                          policy={effective as unknown as PredictivePolicy}
                          defaults={policies.defaults.predictive}
                          onChange={(u) => updateLocalPolicy(eng, u as Record<string, unknown>)}
                        />
                      )}
                      {eng === "pii" && (
                        <PiiPolicyPanel
                          policy={effective as unknown as PiiPolicy}
                          onChange={(u) => updateLocalPolicy(eng, u as Record<string, unknown>)}
                        />
                      )}
                      {eng === "posture" && policies && (
                        <PosturePolicyPanel
                          policy={effective as unknown as PosturePolicy}
                          defaults={policies.defaults.posture}
                          onChange={(u) => updateLocalPolicy(eng, u as Record<string, unknown>)}
                        />
                      )}
                      {eng === "rollback" && (
                        <RollbackPolicyPanel
                          policy={effective as unknown as RollbackPolicy}
                          onChange={(u) => updateLocalPolicy(eng, u as Record<string, unknown>)}
                        />
                      )}
                    </>
                  )}
                </CardContent>
              </Card>

              {/* Posture score breakdown */}
              {eng === "posture" && s?.latestScore && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Gauge className="h-4 w-4 text-green-400" />
                      Latest Score Breakdown
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
                      {Object.entries(s.latestScore).map(([key, val]) => (
                        <div key={key} className="text-center">
                          <div
                            className={`text-2xl font-bold ${
                              val >= 75
                                ? "text-green-400"
                                : val >= 50
                                ? "text-yellow-400"
                                : "text-red-400"
                            }`}
                          >
                            {val}
                          </div>
                          <div className="text-xs text-muted-foreground capitalize">{key}</div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Rollback pending notice */}
              {eng === "rollback" && (s?.pendingRollbacks ?? 0) > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-400" />
                      {s!.pendingRollbacks} Pending Rollback
                      {s!.pendingRollbacks !== 1 ? "s" : ""}
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Navigate to Autonomous Response to execute pending rollbacks.
                    </CardDescription>
                  </CardHeader>
                </Card>
              )}
            </TabsContent>
          );
        })}
      </Tabs>

      <ExplainDialog
        engine={explainEngine}
        open={!!explainEngine}
        onClose={() => setExplainEngine(null)}
      />
    </div>
  );
}
