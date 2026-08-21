import { describe, expect, it } from "vitest";
import { noDataReason, percentageOrNull } from "../metric-availability";

describe("empty-denominator metrics", () => {
  it("does not represent an empty rate as zero", () => {
    expect(percentageOrNull(0, 0)).toBeNull();
    expect(noDataReason("playbook executions", 0)).toBe(
      "No playbook executions have been recorded for this organization.",
    );
  });

  it("preserves measured zero and measured percentages", () => {
    expect(percentageOrNull(0, 4)).toBe(0);
    expect(percentageOrNull(3, 4)).toBe(75);
    expect(noDataReason("chaos simulations", 4)).toBeNull();
  });
});
