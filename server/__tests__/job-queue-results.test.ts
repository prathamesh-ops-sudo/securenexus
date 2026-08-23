import { describe, expect, it } from "vitest";

import { getJobResultStatus, isErrorBearingJobResult } from "../job-queue";

describe("job queue result status", () => {
  it("marks error-bearing worker results as failed", () => {
    const result = { error: "AI model failed", decisionId: "decision-1" };

    expect(isErrorBearingJobResult(result)).toBe(true);
    expect(getJobResultStatus(result)).toBe("failed");
  });

  it("marks ordinary worker results as completed", () => {
    expect(isErrorBearingJobResult({ alertId: "alert-1" })).toBe(false);
    expect(getJobResultStatus({ alertId: "alert-1" })).toBe("completed");
  });
});
