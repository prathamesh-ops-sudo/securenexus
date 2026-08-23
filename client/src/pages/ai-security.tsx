import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, AlertTriangle, Loader2, ChevronLeft, ChevronRight, Lock, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { apiRequest } from "@/lib/queryClient";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

interface SecuritySettings {
  injectionMode: "off" | "flag_and_gate" | "block";
  piiMasking: "mask_identifiers" | "mask_all" | "off";
  aiEnabled: boolean;
  autonomyMode: "observe_only" | "assisted" | "autonomous";
  models: {
    default: string;
    triage: string;
    investigation: string;
  };
  modelPricing: Record<string, { input: number; output: number } | null>;
}

type SecuritySettingsUpdate = Pick<SecuritySettings, "injectionMode" | "piiMasking" | "aiEnabled" | "autonomyMode">;

interface GuardEvent {
  id: string;
  invocation_id: string;
  created_at: string;
  feature: string;
  model_id: string;
  injection_score: number;
  signals: Array<{ rule: string; excerpt: string }>;
  action_taken: string;
  redaction_counts: Array<{ kind: string; count: number }>;
  human_review_required: boolean;
}

function redactionTotal(events: GuardEvent[]): number {
  return events.reduce((total, event) => total + event.redaction_counts.reduce((sum, item) => sum + item.count, 0), 0);
}

interface PageMeta {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

async function fetchEnvelope<T>(url: string): Promise<{ data: T; meta?: PageMeta }> {
  const response = await fetch(url);
  const body = (await response.json()) as { data: T | null; meta?: PageMeta; errors?: Array<{ message: string }> };
  if (!response.ok || body.data === null) throw new Error(body.errors?.[0]?.message || "Request failed");
  return { data: body.data, meta: body.meta };
}

export default function AiSecurityPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedEvent, setSelectedEvent] = useState<GuardEvent | null>(null);
  const [severity, setSeverity] = useState<"" | "suspected" | "likely">("");
  const [feature, setFeature] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const [pendingAutonomyMode, setPendingAutonomyMode] = useState<SecuritySettings["autonomyMode"] | null>(null);
  const settingsQuery = useQuery<SecuritySettings>({
    queryKey: ["/api/ai/security-settings"],
    queryFn: async () => (await fetchEnvelope<SecuritySettings>("/api/ai/security-settings")).data,
  });
  const eventsQuery = useQuery<{ events: GuardEvent[]; meta?: PageMeta }>({
    queryKey: ["/api/ai/guard-events", severity, feature, from, to, page],
    queryFn: async () => {
      const params = new URLSearchParams({ page: String(page), pageSize: "25" });
      if (severity) params.set("severity", severity);
      if (feature) params.set("feature", feature);
      if (from) params.set("from", `${from}T00:00:00.000Z`);
      if (to) params.set("to", `${to}T23:59:59.999Z`);
      const result = await fetchEnvelope<GuardEvent[]>(`/api/ai/guard-events?${params.toString()}`);
      return { events: result.data, meta: result.meta };
    },
  });
  const settingsMutation = useMutation({
    mutationFn: async (settings: SecuritySettingsUpdate) => {
      const response = await apiRequest("PUT", "/api/ai/security-settings", settings);
      return (await response.json()) as SecuritySettings;
    },
    onSuccess: (data) => {
      queryClient.setQueryData(["/api/ai/security-settings"], data);
      toast({ title: "AI security settings saved" });
    },
    onError: (error: Error) =>
      toast({ title: "Could not save AI security settings", description: error.message, variant: "destructive" }),
  });

  if (settingsQuery.isLoading || eventsQuery.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-72" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }
  if (settingsQuery.isError || eventsQuery.isError || !settingsQuery.data) {
    return (
      <div className="p-6 text-sm text-destructive">AI security settings or guard events could not be loaded.</div>
    );
  }

  const settings = settingsQuery.data;
  const update = (change: Partial<SecuritySettingsUpdate>) =>
    settingsMutation.mutate({
      injectionMode: settings.injectionMode,
      piiMasking: settings.piiMasking,
      aiEnabled: settings.aiEnabled,
      autonomyMode: settings.autonomyMode,
      ...change,
    });
  const events = eventsQuery.data?.events ?? [];
  const pageMeta = eventsQuery.data?.meta;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <ShieldCheck className="h-6 w-6" /> AI Security
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Review prompt-injection protections, egress redaction, and human-review gates for this organization.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Models and redaction</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {[
            ["Default / narrative / correlation", settings.models.default],
            ["Triage", settings.models.triage],
            ["Investigation", settings.models.investigation],
          ].map(([tier, model]) => (
            <div key={tier} className="flex items-center justify-between rounded border px-3 py-2 text-sm">
              <span>{tier}</span>
              <code className="text-xs text-muted-foreground">{model}</code>
            </div>
          ))}
          {Array.from(new Set(Object.values(settingsQuery.data.models)))
            .filter((model) => settingsQuery.data.modelPricing?.[model] == null)
            .map((model) => (
              <p key={model} className="text-xs text-muted-foreground">
                {model} cost is not published; invocations still count toward limits and are shown as not published.
              </p>
            ))}
          <div className="text-sm font-medium">Redactions recorded: {redactionTotal(events)}</div>
          <p className="text-xs text-muted-foreground">
            Redactions protect provider egress and are recorded per event; redaction alone does not gate autonomous
            decisions.
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" /> Autonomy mode
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            This tenant-level control governs whether AI recommendations can dispatch response actions.
          </p>
          <div className="grid gap-3 md:grid-cols-3">
            {[
              ["observe_only", "Observe-only", "AI investigates and recommends; it executes nothing."],
              ["assisted", "Assisted", "AI investigates and recommends; every action requires approval."],
              ["autonomous", "Autonomous", "AI can execute only the existing allow-listed actions."],
            ].map(([value, label, description]) => (
              <div
                key={value}
                className={`rounded-lg border p-3 ${settings.autonomyMode === value ? "border-primary bg-primary/5" : ""}`}
              >
                <p className="font-medium">{label}</p>
                <p className="mt-1 text-xs text-muted-foreground">{description}</p>
                {settings.autonomyMode === value && (
                  <p className="mt-2 flex items-center gap-1 text-xs text-primary">
                    <CheckCircle2 className="h-3 w-3" /> Current mode
                  </p>
                )}
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="min-w-[220px] flex-1 space-y-2 text-sm">
              <span className="font-medium">Change mode</span>
              <Select
                value={settings.autonomyMode}
                onValueChange={(value) => {
                  if (value === settings.autonomyMode) return;
                  setPendingAutonomyMode(value as SecuritySettings["autonomyMode"]);
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="observe_only">Observe-only</SelectItem>
                  <SelectItem value="assisted">Assisted</SelectItem>
                  <SelectItem value="autonomous">Autonomous</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <AlertDialog
              open={pendingAutonomyMode !== null}
              onOpenChange={(open) => !open && setPendingAutonomyMode(null)}
            >
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Confirm autonomy mode change</AlertDialogTitle>
                  <AlertDialogDescription>
                    Changing this tenant setting changes how AI recommendations can dispatch actions in this
                    organization. The change will be recorded in the autonomy audit log.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Keep current mode</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => {
                      if (pendingAutonomyMode) update({ autonomyMode: pendingAutonomyMode });
                      setPendingAutonomyMode(null);
                    }}
                  >
                    Confirm change
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
            {settingsMutation.isSuccess && <span className="text-sm text-emerald-600">Mode saved.</span>}
          </div>
          {settingsMutation.isError && <p className="text-sm text-destructive">{settingsMutation.error.message}</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Protection controls</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-5 md:grid-cols-2">
          <label className="space-y-2 text-sm">
            <span className="font-medium">Injection enforcement</span>
            <Select
              value={settings.injectionMode}
              onValueChange={(value) => update({ injectionMode: value as SecuritySettings["injectionMode"] })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="flag_and_gate">Flag and require human review</SelectItem>
                <SelectItem value="block">Block likely injection attempts</SelectItem>
                <SelectItem value="off">Detect only (owner action)</SelectItem>
              </SelectContent>
            </Select>
          </label>
          <label className="space-y-2 text-sm">
            <span className="font-medium">PII masking</span>
            <Select
              value={settings.piiMasking}
              onValueChange={(value) => update({ piiMasking: value as SecuritySettings["piiMasking"] })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="mask_identifiers">Mask identifiers, preserve network evidence</SelectItem>
                <SelectItem value="mask_all">Mask identifiers, IPs, and hostnames</SelectItem>
                <SelectItem value="off">Identifiers visible (secrets remain redacted)</SelectItem>
              </SelectContent>
            </Select>
            <span className="block text-xs text-muted-foreground">
              Masking identifiers keeps IPs, hostnames, hashes, and ports available for detection quality.
            </span>
          </label>
          <label className="flex items-center gap-3 text-sm">
            <Switch
              checked={settings.aiEnabled}
              onCheckedChange={(checked) => update({ aiEnabled: checked })}
              disabled={settingsMutation.isPending}
            />
            <span>{settings.aiEnabled ? "AI analysis enabled" : "AI analysis disabled; no model calls will run"}</span>
          </label>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Guard events</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-4 grid gap-3 md:grid-cols-4">
            <label className="space-y-2 text-sm">
              <span className="font-medium">Feature</span>
              <Input
                value={feature}
                onChange={(event) => {
                  setFeature(event.target.value);
                  setPage(1);
                }}
                placeholder="triage, narrative…"
              />
            </label>
            <label className="space-y-2 text-sm">
              <span className="font-medium">Severity filter</span>
              <Select
                value={severity || "all"}
                onValueChange={(value) => {
                  setSeverity(value === "all" ? "" : (value as "suspected" | "likely"));
                  setPage(1);
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All detections</SelectItem>
                  <SelectItem value="suspected">Suspected</SelectItem>
                  <SelectItem value="likely">Likely</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label className="space-y-2 text-sm">
              <span className="font-medium">From</span>
              <Input
                type="date"
                value={from}
                onChange={(event) => {
                  setFrom(event.target.value);
                  setPage(1);
                }}
              />
            </label>
            <label className="space-y-2 text-sm">
              <span className="font-medium">To</span>
              <Input
                type="date"
                value={to}
                onChange={(event) => {
                  setTo(event.target.value);
                  setPage(1);
                }}
              />
            </label>
          </div>
          {events.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              No AI guard events have been recorded.
            </div>
          ) : (
            <div className="space-y-2">
              {events.map((event) => (
                <button
                  key={event.id}
                  className="w-full rounded-md border p-3 text-left hover:bg-muted/40"
                  onClick={() => setSelectedEvent(event)}
                >
                  <div className="flex items-center gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    <span className="font-medium">{event.feature}</span>
                    <span className="text-muted-foreground">{event.action_taken}</span>
                    <span className="ml-auto">score {event.injection_score}</span>
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {new Date(event.created_at).toLocaleString()} · {event.model_id} · invocation {event.invocation_id}
                  </div>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      <Sheet
        open={selectedEvent !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedEvent(null);
        }}
      >
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Signal details</SheetTitle>
          </SheetHeader>
          {selectedEvent && (
            <div className="space-y-3 pt-6 text-sm">
              <p className="text-muted-foreground">
                Raw evidence is never shown here. Excerpts are redacted before persistence.
              </p>
              {selectedEvent.signals.map((signal) => (
                <div key={signal.rule} className="rounded border p-2">
                  <strong>{signal.rule}</strong>
                  <p className="mt-1 text-muted-foreground">{signal.excerpt}</p>
                </div>
              ))}
              {selectedEvent.redaction_counts.length > 0 && (
                <div className="rounded border p-2">
                  <strong>Provider-egress redactions</strong>
                  <p className="mt-1 text-muted-foreground">
                    Redactions were applied before provider egress. They are recorded for audit and do not by themselves
                    gate autonomous action.
                  </p>
                  <ul className="mt-2 list-disc pl-5 text-muted-foreground">
                    {selectedEvent.redaction_counts.map((redaction) => (
                      <li key={redaction.kind}>
                        {redaction.kind}: {redaction.count}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {selectedEvent.human_review_required && (
                <p className="font-medium text-amber-600">
                  This analysis is gated and requires human review before autonomous action.
                </p>
              )}
              <p className="text-xs text-muted-foreground">Invocation ID: {selectedEvent.invocation_id}</p>
            </div>
          )}
        </SheetContent>
      </Sheet>
      {pageMeta && pageMeta.totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            Page {pageMeta.page} of {pageMeta.totalPages} ({pageMeta.total} events)
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>
              <ChevronLeft className="h-4 w-4" /> Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= pageMeta.totalPages}
              onClick={() => setPage((value) => value + 1)}
            >
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
      {settingsMutation.isPending && (
        <div className="fixed bottom-4 right-4 flex items-center gap-2 rounded bg-background p-2 text-xs shadow">
          <Loader2 className="h-3 w-3 animate-spin" />
          Saving…
        </div>
      )}
    </div>
  );
}
