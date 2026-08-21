import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  send: vi.fn(),
  query: vi.fn(),
}));

vi.mock("@aws-sdk/client-bedrock-runtime", () => ({
  BedrockRuntimeClient: class {
    send = mocks.send;
  },
  InvokeModelCommand: class {
    constructor(public input: unknown) {}
  },
}));

vi.mock("../aws-credentials", () => ({
  getAwsClientConfig: () => ({}),
}));

vi.mock("../db", () => ({
  pool: {
    query: mocks.query,
  },
}));

describe("RAG retrieval truthfulness", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.send.mockResolvedValue({
      body: new TextEncoder().encode(JSON.stringify({ embedding: [0.1], inputTextTokenCount: 1 })),
    });
    mocks.query.mockResolvedValue({ rows: [] });
  });

  it("distinguishes successful empty retrieval from embedding failure", async () => {
    const { vectorSearch } = await import("../ai/vector-search");

    const empty = await vectorSearch("no-match", "attack_techniques", 5, "org-1");
    expect(empty).toEqual({ ok: true, results: [] });

    mocks.send.mockRejectedValueOnce(new Error("embedding unavailable"));
    const failed = await vectorSearch("broken", "attack_techniques", 5, "org-1");
    expect(failed).toMatchObject({ ok: false, code: "RETRIEVAL_FAILED" });
  });

  it("marks failed context retrieval unavailable instead of returning no evidence", async () => {
    mocks.send.mockRejectedValue(new Error("embedding unavailable"));
    const { buildRAGContext, formatRAGContextForPrompt } = await import("../ai/vector-search");

    const context = await buildRAGContext({ title: "Suspicious alert" }, "org-1");
    expect(context.retrievalStatus).toBe("unavailable");
    expect(context.similarPastIncidents).toEqual([]);
    expect(formatRAGContextForPrompt(context)).toContain("Do not infer that no relevant");
  });
});
