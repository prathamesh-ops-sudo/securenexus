import { describe, expect, it, vi } from "vitest";
vi.hoisted(() => {
  process.env.DATABASE_URL ||= "postgresql://localhost/securenexus-test";
  process.env.SESSION_SECRET ||= "test-session-secret-with-at-least-32-characters";
  process.env.S3_BUCKET_NAME ||= "test-bucket";
  process.env.AWS_REGION ||= "us-east-1";
});
import { extractJson } from "../ai";
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

  it("extracts JSON wrapped in a markdown json fence", () => {
    expect(extractJson('```json\n{"severity":"high"}\n```')).toBe('{"severity":"high"}');
  });
});
