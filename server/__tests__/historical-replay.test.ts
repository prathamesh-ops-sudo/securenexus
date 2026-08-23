import { describe, expect, it } from "vitest";

import { buildReplaySelection, deriveReplayOutcome } from "../ai/historical-replay";

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
    expect(deriveReplayOutcome({ escalationRequired: false, falsePositiveLikelihood: 0.9 })).toBe("false_positive");
    expect(deriveReplayOutcome({ escalationRequired: true, falsePositiveLikelihood: 0.1 })).toBe("escalate_human");
    expect(deriveReplayOutcome({ escalationRequired: false, falsePositiveLikelihood: 0.2 })).toBe(
      "needs_investigation",
    );
  });
});
