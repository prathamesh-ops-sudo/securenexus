import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  insert: vi.fn(),
}));

vi.mock("../db", () => ({
  db: {
    insert: mocks.insert,
  },
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
  },
}));

describe("decision receipt persistence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.insert.mockReturnValue({
      values: vi.fn().mockResolvedValue(undefined),
    });
  });

  it("writes a clean redaction receipt instead of treating no redactions as missing", async () => {
    const { persistRedactionReceipt } = await import("../ai/decision-receipts");

    await persistRedactionReceipt({
      orgId: "org-1",
      decisionId: "decision-1",
      invocationId: "invocation-1",
      redactions: [],
    });

    expect(mocks.insert).toHaveBeenCalled();
    const values = mocks.insert.mock.results[0].value.values;
    expect(values).toHaveBeenCalledWith({
      orgId: "org-1",
      decisionId: "decision-1",
      invocationId: "invocation-1",
      redactedClasses: [],
      redacted: false,
    });
  });

  it("writes redacted classes and preserves the source row snapshot", async () => {
    const { persistDecisionEvidence, persistRedactionReceipt } = await import("../ai/decision-receipts");
    const alert = { id: "alert-1", orgId: "org-1", title: "Suspicious alert" } as any;

    await persistDecisionEvidence("org-1", "decision-1", alert, null);
    await persistRedactionReceipt({
      orgId: "org-1",
      decisionId: "decision-1",
      invocationId: "invocation-2",
      redactions: ["ip_address"],
    });

    const evidenceValues = mocks.insert.mock.results[0].value.values;
    expect(evidenceValues).toHaveBeenCalledWith([
      expect.objectContaining({
        orgId: "org-1",
        decisionId: "decision-1",
        sourceTable: "alerts",
        sourcePrimaryKey: "alert-1",
        valueSnapshot: alert,
      }),
    ]);
    const redactionValues = mocks.insert.mock.results[1].value.values;
    expect(redactionValues).toHaveBeenCalledWith(
      expect.objectContaining({ redactedClasses: ["ip_address"], redacted: true }),
    );
  });

  it("stores derived investigation evidence without a source citation", async () => {
    const { persistDecisionEvidence } = await import("../ai/decision-receipts");
    const alert = { id: "alert-1", orgId: "org-1", title: "Suspicious alert" } as any;

    await persistDecisionEvidence("org-1", "decision-1", alert, {
      hypotheses: [
        {
          id: "h1",
          title: "Hypothesis",
          description: "Description",
          type: "unknown",
          evidenceFor: [{ source: "analysis", description: "Derived finding", weight: 0.8 }],
          evidenceAgainst: [],
          confidence: 0.8,
          status: "supported",
        },
      ],
      correlations: {
        relatedAlerts: [],
        relatedIncidents: [],
        timeWindowDays: 90,
        patternDetected: false,
        patternDescription: null,
      },
    } as any);

    const values = mocks.insert.mock.results[0].value.values;
    expect(values).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sourceKind: "investigation_analysis",
          sourceTable: null,
          sourcePrimaryKey: null,
        }),
      ]),
    );
  });

  it("summarizes unmeasured and mixed invocations without fabricating totals", async () => {
    const { summarizeInferenceEntries } = await import("../ai/decision-receipts");

    expect(
      summarizeInferenceEntries([
        {
          model: "model-a",
          promptId: "triage",
          promptVersion: 1,
          inputTokens: 10,
          outputTokens: 5,
          cost: 0.01,
          latency: 20,
        },
        {
          model: "model-b",
          promptId: "triage-v2",
          promptVersion: 2,
          inputTokens: null,
          outputTokens: null,
          cost: null,
          latency: null,
        },
      ]),
    ).toEqual({
      model: "multiple",
      promptId: "multiple",
      promptVersion: null,
      totalInputTokens: 10,
      totalOutputTokens: 5,
      totalCostUsd: 0.01,
      totalLatencyMs: 20,
      unmeasuredInvocationCount: 1,
    });
  });

  it("rejects lifecycle strings at the decision write boundary", async () => {
    const { assertDecisionOutcome } = await import("../ai/decision-receipts");

    expect(() => assertDecisionOutcome("completed")).toThrow("Invalid AI decision outcome");
    expect(() => assertDecisionOutcome(null)).not.toThrow();
    expect(() => assertDecisionOutcome("needs_investigation")).not.toThrow();
  });
});
