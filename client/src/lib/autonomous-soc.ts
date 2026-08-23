export interface OutcomeCount {
  outcome: string;
  count: number;
}

const NO_VERDICT_OUTCOMES = new Set(["failed", "pending_review", "not_recorded"]);

const OUTCOME_LABELS: Record<string, string> = {
  true_positive: "True Positive",
  false_positive: "False Positive",
  auto_resolved: "Auto-Resolved",
  auto_contained: "Auto-Contained",
  escalate_tier2: "Escalated to Tier 2",
  escalate_tier3: "Escalated to Tier 3",
  escalate_human: "Escalated to Human",
  needs_investigation: "Needs Investigation",
  failed: "Failed (no verdict)",
  pending_review: "Pending review (no verdict)",
  not_recorded: "No verdict recorded",
};

export function formatOutcomeLabel(outcome: string): string {
  return (
    OUTCOME_LABELS[outcome] ??
    outcome
      .split("_")
      .filter(Boolean)
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ")
  );
}

export function splitOutcomeCounts(outcomes: Record<string, number>): {
  verdicts: OutcomeCount[];
  lifecycle: OutcomeCount[];
} {
  const verdicts: OutcomeCount[] = [];
  const lifecycle: OutcomeCount[] = [];

  for (const [outcome, count] of Object.entries(outcomes)) {
    (NO_VERDICT_OUTCOMES.has(outcome) ? lifecycle : verdicts).push({ outcome, count });
  }

  return { verdicts, lifecycle };
}
