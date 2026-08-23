import { describe, expect, it } from "vitest";
import { canonicalSerialize, computeDecisionDigest } from "../ai/decision-integrity";
import { getProofRetentionStatus } from "../ai/proof-retention";

describe("decision integrity canonicalization", () => {
  it("is deterministic across object keys and non-semantic array ordering", () => {
    const first = {
      decision: { outcome: "benign", confidence: 0.9 },
      evidence: [
        { id: "b", value: 2 },
        { id: "a", value: 1 },
      ],
    };
    const second = {
      evidence: [
        { value: 1, id: "a" },
        { value: 2, id: "b" },
      ],
      decision: { confidence: 0.9, outcome: "benign" },
    };
    expect(canonicalSerialize(first)).toBe(canonicalSerialize(second));
    expect(computeDecisionDigest(first)).toBe(computeDecisionDigest(second));
  });

  it("changes the digest when a stored receipt field changes", () => {
    const original = { decision: { outcome: "benign" }, evidence: [{ id: "evidence-1", value: "original" }] };
    const mutated = { decision: { outcome: "benign" }, evidence: [{ id: "evidence-1", value: "mutated" }] };
    expect(computeDecisionDigest(original)).not.toBe(computeDecisionDigest(mutated));
  });

  it("exposes the shortest proof-layer retention horizon", () => {
    const createdAt = new Date("2026-01-01T00:00:00.000Z");
    const retention = getProofRetentionStatus(createdAt, new Date("2026-01-15T00:00:00.000Z"));
    expect(retention.effectiveRetentionDays).toBe(30);
    expect(retention.fullExportHorizon).toBe("2026-01-31T00:00:00.000Z");
    expect(retention.completeExportAvailable).toBe(true);
    expect(retention.classes).toHaveLength(7);
  });
});
