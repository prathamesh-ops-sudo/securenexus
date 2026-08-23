import { describe, expect, it } from "vitest";
import { formatOutcomeLabel, splitOutcomeCounts } from "./autonomous-soc";

describe("Autonomous SOC outcome presentation", () => {
  it("separates verdicts from lifecycle states that produced no verdict", () => {
    expect(
      splitOutcomeCounts({
        false_positive: 4,
        true_positive: 2,
        failed: 1,
        pending_review: 3,
        not_recorded: 5,
      }),
    ).toEqual({
      verdicts: [
        { outcome: "false_positive", count: 4 },
        { outcome: "true_positive", count: 2 },
      ],
      lifecycle: [
        { outcome: "failed", count: 1 },
        { outcome: "pending_review", count: 3 },
        { outcome: "not_recorded", count: 5 },
      ],
    });
  });

  it("renders known and fallback keys as human-readable labels", () => {
    expect(formatOutcomeLabel("false_positive")).toBe("False Positive");
    expect(formatOutcomeLabel("pending_review")).toBe("Pending review (no verdict)");
    expect(formatOutcomeLabel("new_future_verdict")).toBe("New Future Verdict");
  });
});
