export interface TenantIntegrityResult {
  decisionId: string;
  status: "verified" | "mismatched" | "unverifiable";
  sequence: number | null;
  reason: string | null;
}

export interface TenantIntegritySummary {
  verifiedCount: number;
  mismatchedCount: number;
  unverifiableCount: number;
  digestedCount: number;
  firstMismatchSequence: number | null;
  chainBreakSequence: number | null;
  chainBreakReason: string | null;
}

export function summarizeTenantIntegrity(results: TenantIntegrityResult[]): TenantIntegritySummary {
  const firstMismatch = results.find((result) => result.status === "mismatched");
  const chainBreak = results.find(
    (result) => result.status === "mismatched" && result.reason?.toLowerCase().includes("chain"),
  );
  return {
    verifiedCount: results.filter((result) => result.status === "verified").length,
    mismatchedCount: results.filter((result) => result.status === "mismatched").length,
    unverifiableCount: results.filter((result) => result.status === "unverifiable").length,
    digestedCount: results.filter((result) => result.status !== "unverifiable").length,
    firstMismatchSequence: firstMismatch?.sequence ?? null,
    chainBreakSequence: chainBreak?.sequence ?? null,
    chainBreakReason: chainBreak?.reason ?? null,
  };
}
