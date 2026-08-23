import { describe, expect, it } from "vitest";
import { summarizeTenantIntegrity } from "./ai-integrity";

describe("summarizeTenantIntegrity", () => {
  it("counts each integrity state and exposes the first mismatched sequence", () => {
    expect(
      summarizeTenantIntegrity([
        { decisionId: "verified", status: "verified", sequence: 1, reason: null },
        { decisionId: "mismatch", status: "mismatched", sequence: 2, reason: "Chain link is broken." },
        { decisionId: "historical", status: "unverifiable", sequence: null, reason: "Predates digests." },
      ]),
    ).toEqual({
      verifiedCount: 1,
      mismatchedCount: 1,
      unverifiableCount: 1,
      digestedCount: 2,
      firstMismatchSequence: 2,
      chainBreakSequence: 2,
      chainBreakReason: "Chain link is broken.",
    });
  });

  it("does not label a digest mismatch as a chain break", () => {
    expect(
      summarizeTenantIntegrity([
        { decisionId: "mismatch", status: "mismatched", sequence: 4, reason: "Digest does not match." },
      ]),
    ).toMatchObject({
      firstMismatchSequence: 4,
      chainBreakSequence: null,
      chainBreakReason: null,
    });
  });

  it("does not call an empty or historical-only tenant a verified chain", () => {
    expect(summarizeTenantIntegrity([])).toMatchObject({
      verifiedCount: 0,
      mismatchedCount: 0,
      unverifiableCount: 0,
      digestedCount: 0,
      firstMismatchSequence: null,
      chainBreakSequence: null,
    });
    expect(
      summarizeTenantIntegrity([
        { decisionId: "historical", status: "unverifiable", sequence: null, reason: "Predates digests." },
      ]),
    ).toMatchObject({
      verifiedCount: 0,
      mismatchedCount: 0,
      unverifiableCount: 1,
      digestedCount: 0,
      firstMismatchSequence: null,
      chainBreakSequence: null,
    });
  });
});
