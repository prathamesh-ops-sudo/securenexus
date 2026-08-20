import { describe, expect, it } from "vitest";
import { classifyGuardEvents, type GuardEvent } from "./ai-guard-state";

const event = (overrides: Partial<GuardEvent> = {}): GuardEvent => ({
  id: "event-1",
  injection_score: 0,
  signals: [{ rule: "system_prompt_probe" }],
  action_taken: "allowed",
  human_review_required: false,
  ...overrides,
});

describe("AI guard banner state", () => {
  it("classifies a human-review event as a genuine gate", () => {
    expect(classifyGuardEvents([event({ injection_score: 2, human_review_required: true })])).toMatchObject({
      kind: "gated",
      signals: ["system_prompt_probe"],
    });
  });

  it("classifies a scored monitor event as recorded without a gate", () => {
    expect(classifyGuardEvents([event({ injection_score: 1 })])).toMatchObject({
      kind: "recorded",
      signals: ["system_prompt_probe"],
    });
  });

  it("prioritizes a genuine gate when recorded and gated events coexist", () => {
    expect(
      classifyGuardEvents([
        event({ id: "recorded", injection_score: 1 }),
        event({ id: "gated", injection_score: 2, human_review_required: true }),
      ]),
    ).toMatchObject({
      kind: "gated",
      events: [{ id: "gated" }, { id: "recorded" }],
    });
  });

  it("ignores clean events", () => {
    expect(classifyGuardEvents([event()])).toBeNull();
  });
});
