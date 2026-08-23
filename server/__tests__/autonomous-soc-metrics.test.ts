import { describe, expect, it } from "vitest";
import { summarizeDecisionMeasurements } from "../ai/autonomous-analyst";

describe("Autonomous SOC measurement summaries", () => {
  it("averages only recorded confidence and decision-time measurements", () => {
    expect(
      summarizeDecisionMeasurements([
        { confidenceScore: 0.8, timeToDecisionMs: 100 },
        { confidenceScore: null, timeToDecisionMs: null },
        { confidenceScore: 0.6, timeToDecisionMs: 300 },
      ]),
    ).toEqual({
      avgConfidence: 0.7,
      confidenceMeasuredCount: 2,
      avgTimeToDecisionMs: 200,
      decisionTimeMeasuredCount: 2,
    });
  });

  it("returns unavailable averages when no measurements were recorded", () => {
    expect(
      summarizeDecisionMeasurements([
        { confidenceScore: null, timeToDecisionMs: null },
        { confidenceScore: null, timeToDecisionMs: null },
      ]),
    ).toEqual({
      avgConfidence: null,
      confidenceMeasuredCount: 0,
      avgTimeToDecisionMs: null,
      decisionTimeMeasuredCount: 0,
    });
  });
});
