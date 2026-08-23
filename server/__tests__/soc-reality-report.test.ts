import { beforeEach, describe, expect, it, vi } from "vitest";
import { pool } from "../db";
import { generateSocRealityReport } from "../ai/soc-reality-report";

vi.mock("../db", () => ({
  pool: { query: vi.fn() },
}));

const query = vi.mocked(pool.query);
let policyThreshold: string | null = "0.9";
let reportDecisions = [
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
];
let reportAdjudications = [
  {
    decisionId: "decision-1",
    adjudicatedOutcome: "benign",
    adjudicatedAt: new Date("2026-08-24T00:00:00Z"),
    isFinal: true,
  },
];
let mttrResult: { averageMinutes: string | null; sampleSize: string; unresolvedExcluded: string } = {
  averageMinutes: null,
  sampleSize: "0",
  unresolvedExcluded: "2",
};

describe("SOC Reality Report", () => {
  beforeEach(() => {
    policyThreshold = "0.9";
    reportDecisions = [
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
    ];
    reportAdjudications = [
      {
        decisionId: "decision-1",
        adjudicatedOutcome: "benign",
        adjudicatedAt: new Date("2026-08-24T00:00:00Z"),
        isFinal: true,
      },
    ];
    mttrResult = { averageMinutes: null, sampleSize: "0", unresolvedExcluded: "2" };
    query.mockClear();
    query.mockImplementation(async (text: string) => {
      if (text.includes("FROM alerts") && text.includes("GROUP BY")) {
        return { rows: [{ source: "Elastic Security", count: "2" }] };
      }
      if (text.includes("FROM ai_decision_adjudications")) {
        return { rows: reportAdjudications };
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
      if (text.includes("FROM auto_response_policies")) {
        return { rows: policyThreshold == null ? [] : [{ threshold: policyThreshold }] };
      }
      if (text.includes("FROM ai_analyst_decisions")) {
        return { rows: reportDecisions };
      }
      if (text.includes("ARRAY_AGG")) return { rows: [{ tactics: ["execution"], techniques: ["T1059"] }] };
      if (text.includes("FROM alerts a")) {
        return { rows: [mttrResult] };
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
    expect(report.dispositionMix.counts).toEqual({ false_positive: 1 });
    expect(report.dispositionMix.verdictBelowActionThresholdCount).toBe(0);
    expect(report.dispositionMix.confidenceUnavailableCount).toBe(0);
    expect(report.autoCloseCandidates).toEqual({
      count: 1,
      threshold: 0.9,
      decisionIds: ["decision-1"],
      unavailableReason: null,
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
      measurementDefinition:
        "Alert creation to linked incident resolution; alerts without a linked resolved incident are excluded.",
    });
    expect(report.runCost).toEqual({
      inputTokens: null,
      outputTokens: null,
      costUsd: null,
      unmeasuredInvocations: 1,
    });
  });

  it("reports auto-close candidates as unavailable without an active policy", async () => {
    policyThreshold = null;

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

    expect(report.autoCloseCandidates).toEqual({
      count: null,
      threshold: null,
      decisionIds: [],
      unavailableReason: "Unavailable: no active auto-response policy is configured for this tenant.",
    });
  });

  it("separates below-threshold verdicts from abstentions", async () => {
    reportDecisions = [
      {
        id: "decision-1",
        outcome: "false_positive",
        confidenceScore: 0.7,
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
      {
        id: "decision-3",
        outcome: "false_positive",
        confidenceScore: null,
        safetyVetoes: [],
        retrievalStatus: "empty",
      },
    ];

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

    expect(report.dispositionMix).toMatchObject({
      counts: { false_positive: 2 },
      abstentionCount: 1,
      verdictBelowActionThresholdCount: 1,
      confidenceUnavailableCount: 1,
    });
    expect(report.dispositionMix.counts).not.toHaveProperty("abstention");
    expect(report.autoCloseCandidates.count).toBe(0);
  });

  it("gives final adjudications precedence over newer provisional judgements", async () => {
    reportAdjudications = [
      {
        decisionId: "decision-1",
        adjudicatedOutcome: "benign",
        adjudicatedAt: new Date("2026-08-23T00:00:00Z"),
        isFinal: true,
      },
      {
        decisionId: "decision-1",
        adjudicatedOutcome: "malicious",
        adjudicatedAt: new Date("2026-08-24T00:00:00Z"),
        isFinal: false,
      },
    ];

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

    expect(report.humanAgreement).toMatchObject({
      agreed: 1,
      definitive: 1,
      coverage: { adjudicated: 1, replayed: 2 },
    });
  });

  it("reports linked resolved alerts separately from unresolved and incidentless alerts", async () => {
    mttrResult = { averageMinutes: "30", sampleSize: "1", unresolvedExcluded: "2" };

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

    expect(report.mttrBaseline).toEqual({
      averageMinutes: 30,
      sampleSize: 1,
      unresolvedExcluded: 2,
      unavailableReason: null,
      measurementDefinition:
        "Alert creation to linked incident resolution; alerts without a linked resolved incident are excluded.",
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
