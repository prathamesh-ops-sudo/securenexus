export interface GuardEvent {
  id: string;
  injection_score: number;
  signals: Array<{ rule?: string }>;
  action_taken: string;
  human_review_required: boolean;
}

export interface AiGuardBannerState {
  kind: "gated" | "recorded";
  events: GuardEvent[];
  signals: string[];
}

export function classifyGuardEvents(events: GuardEvent[]): AiGuardBannerState | null {
  const gatedEvents = events.filter((event) => event.human_review_required);
  const recordedEvents = events.filter((event) => !event.human_review_required && event.injection_score > 0);
  const relevantEvents = [...gatedEvents, ...recordedEvents];

  if (relevantEvents.length === 0) return null;

  const signals = Array.from(
    new Set(relevantEvents.flatMap((event) => event.signals.map((signal) => signal.rule).filter(Boolean) as string[])),
  );

  return {
    kind: gatedEvents.length > 0 ? "gated" : "recorded",
    events: relevantEvents,
    signals,
  };
}
