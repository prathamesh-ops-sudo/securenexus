import { describe, expect, it } from "vitest";
import type { AiAnalystDecision, AiInferenceLog } from "@shared/schema";
import { auditorSection, formatInvocationForExport, getRetrievalExportState } from "../routes/ai/auditor-export";

describe("AI auditor export honesty helpers", () => {
  it("marks empty proof sections with an explicit absent reason", () => {
    expect(auditorSection([], "No evidence was recorded.")).toEqual({
      items: [],
      absentReason: "No evidence was recorded.",
    });
    expect(auditorSection([{ id: "evidence-1" }], "No evidence was recorded.")).toEqual({
      items: [{ id: "evidence-1" }],
      absentReason: null,
    });
  });

  it("represents unmeasured model telemetry without converting it to zero", () => {
    const invocation = {
      inputTokens: null,
      outputTokens: null,
      latencyMs: null,
      costEstimateUsd: null,
    } as unknown as AiInferenceLog;
    const exported = formatInvocationForExport(invocation);
    expect(exported).toMatchObject({
      inputTokens: "unmeasured",
      outputTokens: "unmeasured",
      latencyMs: "unmeasured",
      costEstimateUsd: "unmeasured",
    });
  });

  it("preserves retrieval state and explains unavailable retrieval", () => {
    expect(getRetrievalExportState({ retrievalStatus: "empty" } as AiAnalystDecision)).toEqual({
      state: "empty",
      reason: null,
    });
    expect(getRetrievalExportState({ retrievalStatus: "unavailable" } as AiAnalystDecision)).toEqual({
      state: "unavailable",
      reason: "The retrieval attempt was unavailable.",
    });
    expect(getRetrievalExportState({ retrievalStatus: null } as AiAnalystDecision)).toEqual({
      state: null,
      reason: "Retrieval state was not recorded for this decision.",
    });
  });
});
