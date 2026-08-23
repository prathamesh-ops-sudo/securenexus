import { beforeEach, describe, expect, it, vi } from "vitest";
import { pool } from "../db";
import { generateSocRealityReport } from "../ai/soc-reality-report";

vi.mock("../db", () => ({
  pool: { query: vi.fn() },
}));

const query = vi.mocked(pool.query);

describe("SOC Reality Report", () => {
  beforeEach(() => {
    query.mockClear();
    query.mockImplementation(async (text: string) => {
      if (text.includes("FROM alerts") && text.includes("GROUP BY")) {
        return { rows: [{ source: "Elastic Security", count: "2" }] };
      }
      if (text.includes("FROM ai_decision_adjudications")) {
        return {
          rows: [
            {
              decisionId: "decision-1",
              adjudicatedOutcome: "benign",
              adjudicatedAt: new Date("2026-08-24T00:00:00Z"),
            },
          ],
        };
      }
      if (text.includes("FROM ai_decision_evidence")) {
        return { rows: [{ decisionId: "decision-1", count: "1" }] };
      }
      if (text.includes("FROM ai_inference_log")) {
        return {
          rows: [
            {
              inputTokens: null,
              outputTokens: null,
              costUsd: null,
              unmeasured: "1",
            },
          ],
        };
      }
      if (text.includes("FROM auto_response_policies")) return { rows: [{ threshold: "0.9" }] };
      if (text.includes("FROM ai_analyst_decisions")) {
        return {
          rows: [
            {
              id: "decision-1",
              outcome: "false_positive",
              confidenceScore: 0.95,
              safetyVetoes: [],
              retrievalStatus: "empty",
            },
            {
              id: "decision-2",
              outcome: null,
              confidenceScore: null,
              safetyVetoes: null,
              retrievalStatus: "unavailable",
            },
          ],
        };
      }
      if (text.includes("ARRAY_AGG")) return { rows: [{ tactics: ["execution"], techniques: ["T1059"] }] };
      if (text.includes("FROM alerts a")) {
        return { rows: [{ averageMinutes: null, sampleSize: "0", unresolvedExcluded: "2" }] };
      }
      throw new Error(`Unexpected report query: ${text}`);
    });
  });

  it("reconciles measured coverage, abstentions, missing evidence, policy candidates, and cost", async () => {
    const report = await generateSocRealityReport("org-a", {
      id: "run-a",
      fromAt: new Date("2026-08-23T00:00:00Z"),
      toAt: new Date("2026-08-24T00:00:00Z"),
      source: null,
      severity: null,
      status: "completed",
      totalCount: 2,
      processedCount: 2,
    });

    expect(report.alertsInWindow).toEqual({
      total: 2,
      bySource: [{ source: "Elastic Security", count: 2 }],
    });
    expect(report.replayCoverage).toEqual({
      replayed: 2,
      inWindow: 2,
      rate: null,
      rateReason: "Rate withheld until 20 items; denominator is 2.",
    });
    expect(report.dispositionMix.abstentionCount).toBe(1);
    expect(report.dispositionMix.counts).toEqual({ false_positive: 1, abstention: 1 });
    expect(report.autoCloseCandidates).toEqual({
      count: 1,
      threshold: 0.9,
      decisionIds: ["decision-1"],
    });
    expect(report.whatWeCouldNotSee).toMatchObject({
      replayedDecisions: 2,
      retrievalUnavailable: 1,
      retrievalNotAttempted: 0,
      zeroEvidenceRows: 1,
      decisionIds: ["decision-2"],
    });
    expect(report.mttrBaseline).toEqual({
      averageMinutes: null,
      sampleSize: 0,
      unresolvedExcluded: 2,
      unavailableReason: "No alerts in the window reached a terminal resolved state.",
    });
    expect(report.runCost).toEqual({
      inputTokens: null,
      outputTokens: null,
      costUsd: null,
      unmeasuredInvocations: 1,
    });
  });

  it("keeps report queries tenant-scoped", async () => {
    await generateSocRealityReport("org-a", {
      id: "run-a",
      fromAt: new Date("2026-08-23T00:00:00Z"),
      toAt: new Date("2026-08-24T00:00:00Z"),
      source: null,
      severity: null,
      status: "failed",
      totalCount: 2,
      processedCount: 1,
    });

    expect(query.mock.calls.length).toBe(8);
    for (const [text, values] of query.mock.calls) {
      expect(text).toContain("org_id = $1");
      expect(values?.[0]).toBe("org-a");
    }
  });
});
