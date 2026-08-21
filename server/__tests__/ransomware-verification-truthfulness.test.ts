import { describe, expect, it } from "vitest";
import { evaluateBackupMetadata } from "../routes/ransomware-defense";

describe("backup verification truthfulness", () => {
  it("does not claim restorability from clean metadata", () => {
    const result = evaluateBackupMetadata({
      encryptionStatus: "encrypted",
      retentionDays: 90,
      rpoHours: 4,
    });

    expect(result.status).toBe("metadata_checked");
    expect(result.restoreTestResult).toBe("not_tested");
    expect(result.restorability).toBe("unverified");
    expect(result.nextScheduledVerification).toBeNull();
    expect(result.verificationDurationSeconds).toBeNull();
  });

  it("preserves metadata issues without converting them into a restore-test result", () => {
    const result = evaluateBackupMetadata({
      encryptionStatus: "unknown",
      retentionDays: 7,
      rpoHours: 48,
    });

    expect(result.status).toBe("metadata_issues");
    expect(result.issues.length).toBeGreaterThan(0);
    expect(result.restoreTestResult).toBe("not_tested");
    expect(result.restorability).toBe("unverified");
    expect(result.nextScheduledVerification).toBeNull();
  });
});
