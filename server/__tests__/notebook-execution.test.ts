import { describe, expect, it } from "vitest";
import type { HuntExecutionResult } from "../hunt-engine";
import { recordNotebookStepExecution } from "../notebook-execution";

const baseStep = { id: "step-1", title: "Test step", eventCount: null };

function result(status: HuntExecutionResult["status"], reason?: string): HuntExecutionResult {
  return {
    status,
    eventCount: 0,
    events: [],
    executionDurationMs: 12,
    targetTable: "alerts",
    explanation: `${status} explanation`,
    reason,
  };
}

describe("notebook step execution state", () => {
  it("records rejected steps as rejected with a reason, not zero-match success", () => {
    const steps = recordNotebookStepExecution([baseStep], 0, result("rejected", "Unsupported condition"));

    expect(steps?.[0]).toMatchObject({
      status: "rejected",
      reason: "Unsupported condition",
      eventCount: null,
      resultSummary: "Rejected: Unsupported condition",
    });
  });

  it("records failed steps as failed with a reason, not zero-match success", () => {
    const steps = recordNotebookStepExecution([baseStep], 0, result("failed", "Database unavailable"));

    expect(steps?.[0]).toMatchObject({
      status: "failed",
      reason: "Database unavailable",
      eventCount: null,
      resultSummary: "Failed: Database unavailable",
    });
  });
});
