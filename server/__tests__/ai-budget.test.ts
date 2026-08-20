import { beforeEach, describe, expect, it, vi } from "vitest";

const { query } = vi.hoisted(() => ({
  query: vi.fn(),
}));

vi.mock("../db", () => ({
  pool: { query },
}));

import { checkBudget, trackUsage } from "../ai/budget";

describe("AI budget accounting", () => {
  beforeEach(() => {
    query.mockReset();
  });

  it("counts unknown-cost invocations without adding published spend", async () => {
    query
      .mockResolvedValueOnce({ rows: [{ plan_tier: "free" }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ daily_spend_usd: 0, budget_usd: 5 }] });

    await trackUsage("org-a", {
      inputTokens: 10,
      outputTokens: 5,
      costUsd: null,
      modelId: "us.openai.gpt-5.6-terra",
      latencyMs: 25,
    });

    const updateCall = query.mock.calls[2] as [string, unknown[]];
    expect(updateCall[0]).toContain("daily_invocations = daily_invocations + 1");
    expect(updateCall[1][1]).toBeNull();
    expect(updateCall[0]).toContain("COALESCE($2::double precision, 0)");
  });

  it("enforces the invocation cap independently of published cost", async () => {
    query
      .mockResolvedValueOnce({ rows: [{ plan_tier: "free" }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({
        rows: [
          {
            org_id: "org-a",
            budget_usd: 5,
            invocation_cap: 500,
            daily_spend_usd: 0,
            daily_invocations: 500,
            daily_input_tokens: 100,
            daily_output_tokens: 100,
            last_reset_at: new Date(),
            updated_at: new Date(),
          },
        ],
      });

    await expect(checkBudget("org-a")).resolves.toMatchObject({
      allowed: false,
      reason: expect.stringContaining("invocation cap"),
    });
  });
});
