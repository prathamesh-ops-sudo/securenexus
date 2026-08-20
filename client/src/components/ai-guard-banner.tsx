import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

interface GuardEvent {
  id: string;
  injection_score: number;
  signals: Array<{ rule?: string }>;
  action_taken: string;
  human_review_required: boolean;
}

async function fetchGuardEvents(scope: "alertId" | "incidentId", id: string): Promise<GuardEvent[]> {
  const response = await fetch(`/api/ai/guard-events?${scope}=${encodeURIComponent(id)}&page=1&pageSize=100`);
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
  const gatedEvents = events.filter((event) => event.human_review_required || event.injection_score > 0);
  if (gatedEvents.length === 0) return null;
  const signals = Array.from(
    new Set(gatedEvents.flatMap((event) => event.signals.map((signal) => signal.rule).filter(Boolean))),
  );

  return (
    <Card className="border-amber-500/50 bg-amber-500/5" data-testid="ai-guard-banner">
      <CardContent className="flex items-start gap-3 p-4">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">AI analysis flagged for human review</h2>
            <Badge className="bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100">
              Human review required
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Persisted AI guard events for this {alertId ? "alert" : "incident"} detected untrusted instructions. No
            autonomous action should rely on the flagged analysis.
          </p>
          {signals.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
              <span className="font-medium">Detected signals:</span>
              {signals.map((signal) => (
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
