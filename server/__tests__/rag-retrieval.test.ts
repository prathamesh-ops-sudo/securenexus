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
    expect(formatRAGContextForPrompt(context)).not.toContain("HISTORICAL & KNOWLEDGE BASE CONTEXT (RAG)");
  });

  it("marks successful empty and populated searches distinctly", async () => {
    const { buildRAGContext } = await import("../ai/vector-search");

    const empty = await buildRAGContext({ title: "No matching alert" }, "org-1");
    expect(empty.retrievalStatus).toBe("empty");

    mocks.query.mockResolvedValue({
      rows: [
        {
          id: "knowledge-1",
          category: "attack_techniques",
          source_type: "mitre",
          source_id: "T1059",
          title: "Command and Scripting Interpreter",
          content: "Command execution",
          metadata: { techniqueId: "T1059" },
          similarity: "0.9",
        },
      ],
    });
    const available = await buildRAGContext({ title: "Command execution" }, "org-1");
    expect(available.retrievalStatus).toBe("available");
  });

  it("marks failed historical retrieval as unavailable without evidence or confidence provenance", async () => {
    const { formatThreatIntelForPrompt } = await import("../ai");
    const prompt = formatThreatIntelForPrompt({
      enrichmentResults: [],
      osintMatches: [],
      summary: "",
      historicalContext: {
        similarPastIncidents: [],
        relatedAttackTechniques: [],
        relevantCveAdvisories: [],
        ragSummary: "",
        retrievalStatus: "unavailable",
        retrievalError: "knowledge base unavailable",
      },
      retrievalUnavailable: true,
    });

    expect(prompt).toContain("HISTORICAL RETRIEVAL STATUS: UNAVAILABLE");
    expect(prompt).toContain("Do not cite the failed retrieval");
    expect(prompt).toContain("count it as evidence consulted");
    expect(prompt).not.toContain("SIMILAR PAST INCIDENTS:");
    expect(prompt).not.toContain("Matched 0");
  });

  it("keeps retrieval unattempted distinct when no context was supplied", async () => {
    const { resolveRetrievalStatus } = await import("../ai");

    expect(resolveRetrievalStatus()).toBe("not_attempted");
    expect(resolveRetrievalStatus({ enrichmentResults: [], osintMatches: [] } as any)).toBe("empty");
  });
});
