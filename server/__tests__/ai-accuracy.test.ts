import { describe, expect, it, vi } from "vitest";
import {
  ACCURACY_MINIMUM_SAMPLE,
  calculateAccuracy,
  getAccuracyReport,
  mapAiOutcome,
  selectLatestAdjudication,
} from "../ai/accuracy";
import { pool } from "../db";
import { bodySchemas } from "../request-validator";

const decision = (id: string, outcome: string | null, confidenceScore = 0.8) => ({
  id,
  orgId: "org-a",
  outcome,
  confidenceScore,
  createdAt: new Date("2026-08-23T00:00:00Z"),
});

const adjudication = (decisionId: string, outcome: "malicious" | "benign" | "inconclusive", isFinal = true) => ({
  id: `${decisionId}-${outcome}-${isFinal}`,
  orgId: "org-a",
  decisionId,
  alertId: null,
  adjudicatedOutcome: outcome,
  source: "manual_review" as const,
  actorUserId: "user",
  rationale: "reviewed",
  adjudicatedAt: new Date("2026-08-23T00:00:00Z"),
  isFinal,
  createdAt: new Date("2026-08-23T00:00:00Z"),
});

describe("AI accuracy", () => {
  it("maps every supported outcome and reports unmapped values", () => {
    expect(mapAiOutcome("true_positive")).toBe("malicious");
    expect(mapAiOutcome("auto_resolved")).toBe("benign");
    expect(mapAiOutcome("future_outcome")).toBeNull();
    const report = calculateAccuracy(
      [decision("1", "future_outcome")],
      [adjudication("1", "malicious")],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    expect(report.unmappedCount).toBe(1);
  });

  it("keeps inconclusive and unmapped counts disjoint and reconcilable", () => {
    const report = calculateAccuracy(
      [
        decision("tp", "true_positive"),
        decision("inconclusive", "future_outcome"),
        decision("unmapped", "future_outcome"),
      ],
      [
        adjudication("tp", "malicious"),
        adjudication("inconclusive", "inconclusive"),
        adjudication("unmapped", "benign"),
      ],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    const matrixTotal = Object.values(report.matrix).reduce((total, count) => total + count, 0);
    expect(report.inconclusiveCount).toBe(1);
    expect(report.unmappedCount).toBe(1);
    expect(matrixTotal + report.inconclusiveCount + report.unmappedCount).toBe(report.adjudicatedCount);
  });

  it("computes TP, TN, FP, FN and hides rates below the named threshold", () => {
    const report = calculateAccuracy(
      [
        decision("tp", "true_positive"),
        decision("tn", "false_positive"),
        decision("fp", "true_positive"),
        decision("fn", "false_positive"),
      ],
      [
        adjudication("tp", "malicious"),
        adjudication("tn", "benign"),
        adjudication("fp", "benign"),
        adjudication("fn", "malicious"),
      ],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    expect(report.matrix).toEqual({ truePositive: 1, trueNegative: 1, falsePositive: 1, falseNegative: 1 });
    expect(report.insufficientData).toBe(true);
    expect(report.rates.recall).toBeNull();
    expect(report.minimumSample.threshold).toBe(ACCURACY_MINIMUM_SAMPLE);
  });

  it("returns null with reasons for zero denominators", () => {
    const report = calculateAccuracy(
      [decision("1", "true_positive")],
      [adjudication("1", "inconclusive")],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    expect(report.rates.agreementRate).toBeNull();
    expect(report.rates.agreementRateReason).toContain("Fewer than");
  });

  it("selects the latest final, or latest provisional when no final exists", () => {
    const provisional = adjudication("1", "benign", false);
    const final = adjudication("1", "malicious", true);
    final.adjudicatedAt = new Date("2026-08-24T00:00:00Z");
    expect(selectLatestAdjudication([provisional, final]).final).toBe(final);
    expect(selectLatestAdjudication([provisional]).provisional).toBe(provisional);
  });

  it("excludes adjudications from another tenant", () => {
    const report = calculateAccuracy(
      [decision("1", "true_positive")],
      [{ ...adjudication("1", "malicious"), orgId: "org-b" }],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    expect(report.decisionsTotal).toBe(1);
    expect(report.adjudicatedCount).toBe(0);
    expect(report.matrix).toEqual({ truePositive: 0, trueNegative: 0, falsePositive: 0, falseNegative: 0 });
  });

  it("requires an explicit rationale for feedback adjudications", () => {
    const result = bodySchemas.aiFeedback.safeParse({
      resourceType: "decision",
      resourceId: "decision-1",
      rating: 1,
      adjudicatedOutcome: "malicious",
    });
    expect(result.success).toBe(false);
  });

  it("keeps ten fixed calibration deciles and marks sparse buckets", () => {
    const report = calculateAccuracy(
      [decision("1", "false_positive", 0.85)],
      [adjudication("1", "benign")],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    expect(report.calibration).toHaveLength(10);
    expect(report.calibration[8]).toMatchObject({
      label: "0.8–0.9",
      count: 1,
      inconclusiveCount: 0,
      observedMaliciousRate: 0,
      bucketMidpoint: 0.85,
      insufficientData: true,
    });
  });

  it("excludes inconclusive adjudications from calibration denominators", () => {
    const report = calculateAccuracy(
      [decision("known", "true_positive", 0.55), decision("unknown", "true_positive", 0.55)],
      [adjudication("known", "malicious"), adjudication("unknown", "inconclusive")],
      "2026-08-01",
      "2026-09-01",
      "org-a",
    );
    expect(report.calibration[5]).toMatchObject({
      count: 1,
      inconclusiveCount: 1,
      observedMaliciousRate: 1,
      insufficientData: true,
    });
  });

  it("loads adjudications for decisions in the window even when judgements postdate it", async () => {
    const query = vi.spyOn(pool, "query");
    query
      .mockResolvedValueOnce({
        rows: [decision("1", "true_positive")],
      } as never)
      .mockResolvedValueOnce({
        rows: [
          {
            ...adjudication("1", "malicious"),
            adjudicatedAt: new Date("2026-09-15T00:00:00Z"),
          },
        ],
      } as never);

    try {
      const report = await getAccuracyReport("org-a", "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z");
      expect(report.adjudicatedCount).toBe(1);
      expect(query.mock.calls[1]?.[0]).toContain("d.created_at >= $2::timestamptz");
      expect(query.mock.calls[1]?.[0]).toContain("d.created_at < $3::timestamptz");
      expect(query.mock.calls[1]?.[1]).toEqual(["org-a", "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z"]);
    } finally {
      query.mockRestore();
    }
  });
});
