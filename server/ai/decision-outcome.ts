export type DerivedDecisionOutcome = "false_positive" | "escalate_human" | "needs_investigation";

export function deriveDecisionOutcome(result: {
  escalationRequired: boolean;
  falsePositiveLikelihood: number;
}): DerivedDecisionOutcome {
  if (result.falsePositiveLikelihood >= 0.8) return "false_positive";
  if (result.escalationRequired) return "escalate_human";
  return "needs_investigation";
}
