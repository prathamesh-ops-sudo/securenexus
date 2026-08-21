import type { HuntExecutionResult } from "./hunt-engine";

export function recordNotebookStepExecution(
  steps: Record<string, unknown>[],
  stepIndex: number,
  result: HuntExecutionResult,
  executedAt = new Date(),
): Record<string, unknown>[] | null {
  if (stepIndex < 0 || stepIndex >= steps.length) return null;

  const nextSteps = [...steps];
  nextSteps[stepIndex] = {
    ...nextSteps[stepIndex],
    status: result.status,
    reason: result.reason || null,
    resultSummary:
      result.status === "completed"
        ? `${result.eventCount} events found in ${result.executionDurationMs}ms`
        : `${result.status === "rejected" ? "Rejected" : "Failed"}: ${result.reason || result.explanation}`,
    lastExecutedAt: executedAt.toISOString(),
    eventCount: result.status === "completed" ? result.eventCount : null,
  };
  return nextSteps;
}
