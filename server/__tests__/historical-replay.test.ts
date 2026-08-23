import { describe, expect, it } from "vitest";

import { buildReplayDecisionFields, buildReplaySelection } from "../ai/historical-replay";
import { deriveDecisionOutcome } from "../ai/decision-outcome";

describe("historical replay", () => {
  it("builds a tenant-scoped deterministic selection with optional filters", () => {
    const selection = buildReplaySelection({
      orgId: "org-a",
      fromAt: new Date("2026-08-01T00:00:00Z"),
      toAt: new Date("2026-09-01T00:00:00Z"),
      source: "Elastic Security",
      severity: "high",
    });
    expect(selection.where).toContain("org_id = $1");
    expect(selection.where).toContain("detected_at >= $2");
    expect(selection.where).toContain("detected_at < $3");
    expect(selection.where).toContain("source = $4");
    expect(selection.where).toContain("severity = $5");
    expect(selection.values).toEqual([
      "org-a",
      new Date("2026-08-01T00:00:00Z"),
      new Date("2026-09-01T00:00:00Z"),
      "Elastic Security",
      "high",
    ]);
  });

  it("derives only supported decision outcomes from a replay verdict", () => {
    expect(deriveDecisionOutcome({ escalationRequired: false, falsePositiveLikelihood: 0.9 })).toBe("false_positive");
    expect(deriveDecisionOutcome({ escalationRequired: true, falsePositiveLikelihood: 0.1 })).toBe("escalate_human");
    expect(deriveDecisionOutcome({ escalationRequired: false, falsePositiveLikelihood: 0.2 })).toBe(
      "needs_investigation",
    );
  });

  it("persists replay confidence and measured latency without fabricating confidence", () => {
    expect(
      buildReplayDecisionFields({ escalationRequired: true, falsePositiveLikelihood: 0.1, confidence: 0.87 }, 1432),
    ).toEqual({
      outcome: "escalate_human",
      confidenceScore: 0.87,
      timeToDecisionMs: 1432,
    });
    expect(
      buildReplayDecisionFields({ escalationRequired: false, falsePositiveLikelihood: 0.1 }, 27).confidenceScore,
    ).toBeNull();
  });
});
