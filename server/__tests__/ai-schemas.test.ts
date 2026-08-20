import { describe, expect, it } from "vitest";
import { sanitizeModelOutput, triageOutputSchema } from "../ai/schemas";

describe("AI output schemas", () => {
  it("rejects invalid severity, priority, and technique values", () => {
    const result = triageOutputSchema.safeParse({
      severity: "urgent",
      priority: 9,
      category: "test",
      recommendedAction: "test",
      reasoning: "test",
      mitreTactic: "test",
      mitreTechnique: "T999",
      killChainPhase: "test",
      falsePositiveLikelihood: 0.5,
      falsePositiveReasoning: "test",
      relatedIocs: [],
      nistClassification: "test",
      escalationRequired: false,
      containmentAdvice: "test",
    });
    expect(result.success).toBe(false);
  });

  it("removes control, zero-width, and bidi characters from model strings", () => {
    expect(sanitizeModelOutput("safe\u0000\u200b\u202e text")).toBe("safe text");
  });
});
