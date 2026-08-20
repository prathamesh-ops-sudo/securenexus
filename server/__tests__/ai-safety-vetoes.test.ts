import { describe, expect, it } from "vitest";
import { getGuardVetoes } from "../ai/safety-vetoes";

describe("AI safety veto derivation", () => {
  it("does not veto solely because provider-egress redactions were recorded", () => {
    expect(
      getGuardVetoes({
        injectionScore: 0,
        schemaRetryUsed: false,
        unverifiedCitations: false,
        redactionRemovedContent: true,
      }),
    ).toEqual([]);
  });

  it("derives vetoes from unsafe guard outcomes", () => {
    expect(
      getGuardVetoes({
        injectionScore: 2,
        withheld: true,
        schemaRetryUsed: true,
        unverifiedCitations: true,
      }),
    ).toEqual(["injection_detected", "analysis_withheld", "schema_retry_used", "unverified_citations"]);
  });
});
