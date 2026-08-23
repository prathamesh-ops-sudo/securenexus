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
});
