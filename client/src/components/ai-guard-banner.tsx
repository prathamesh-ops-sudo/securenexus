import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { classifyGuardEvents, type GuardEvent } from "@/lib/ai-guard-state";

async function fetchGuardEvents(scope: "alertId" | "incidentId", id: string): Promise<GuardEvent[]> {
  const response = await fetch(`/api/ai/guard-events/related?${scope}=${encodeURIComponent(id)}`);
  const body = (await response.json()) as { data: GuardEvent[] | null; errors?: Array<{ message?: string }> };
  if (!response.ok || !body.data) throw new Error(body.errors?.[0]?.message || "Unable to load AI guard state");
  return body.data;
}

export function AiGuardBanner({ alertId, incidentId }: { alertId?: string; incidentId?: string }) {
  const scope = alertId ? "alertId" : "incidentId";
  const id = alertId ?? incidentId;
  const { data: events = [], isLoading } = useQuery<GuardEvent[]>({
    queryKey: ["/api/ai/guard-events", scope, id],
    queryFn: () => fetchGuardEvents(scope, id as string),
    enabled: !!id,
  });

  if (isLoading || events.length === 0) return null;
  const state = classifyGuardEvents(events);
  if (!state) return null;
  const isGated = state.kind === "gated";

  return (
    <Card className="border-amber-500/50 bg-amber-500/5" data-testid="ai-guard-banner">
      <CardContent className="flex items-start gap-3 p-4">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">
              {isGated ? "AI analysis flagged for human review" : "AI analysis recorded a safety detection"}
            </h2>
            <Badge className="bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100">
              {isGated ? "Human review required" : "Recorded; no gate"}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            {isGated
              ? `Persisted AI guard events for this ${alertId ? "alert" : "incident"} indicate that the analysis requires human review. No autonomous action should rely on the flagged analysis.`
              : `Persisted AI guard events for this ${alertId ? "alert" : "incident"} recorded an injection signal, but this event did not require human review under the current enforcement mode.`}
          </p>
          {state.signals.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
              <span className="font-medium">{isGated ? "Detected signals:" : "Recorded signals:"}</span>
              {state.signals.map((signal) => (
                <Badge key={signal} variant="outline" className="text-[10px]">
                  {signal}
                </Badge>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
