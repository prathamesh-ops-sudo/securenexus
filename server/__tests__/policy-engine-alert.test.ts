import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Alert, AutoResponsePolicy } from "@shared/schema";

const policies: AutoResponsePolicy[] = [];
const dispatchAction = vi.fn(
  async (actionType: string, _config: Record<string, unknown>, context: Record<string, unknown>) => ({
    actionType,
    status: "withheld" as const,
    message: "withheld",
    executedAt: new Date().toISOString(),
    details: { context },
  }),
);

vi.mock("../storage", () => ({
  storage: {
    getAutoResponsePolicies: vi.fn(async () => policies),
    updateAutoResponsePolicy: vi.fn(async () => undefined),
  },
}));
vi.mock("../action-dispatcher", () => ({ dispatchAction }));

const { evaluateAndDispatchAlertPolicies } = await import("../policy-engine");

function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "alert-1",
    orgId: "org-1",
    source: "native-sensor",
    category: "threat",
    severity: "high",
    title: "Test alert",
    description: null,
    status: "new",
    suppressed: false,
    ...overrides,
  } as Alert;
}

describe("alert-triggered response policies", () => {
  beforeEach(() => {
    policies.length = 0;
    dispatchAction.mockClear();
  });

  it("matches persisted alert fields and dispatches without an incident", async () => {
    policies.push({
      id: "policy-1",
      orgId: "org-1",
      name: "Alert policy",
      triggerType: "alert_created",
      conditions: { categories: ["threat"], sources: ["native-sensor"] },
      severityFilter: ["high"],
      actions: [{ actionType: "notify", config: {} }],
      status: "active",
      confidenceThreshold: 0,
      cooldownMinutes: 0,
      maxActionsPerHour: 10,
      executionCount: 0,
    } as AutoResponsePolicy);

    const results = await evaluateAndDispatchAlertPolicies(alert());

    expect(results[0]?.status).toBe("withheld");
    expect(dispatchAction).toHaveBeenCalledWith(
      "notify",
      {},
      expect.objectContaining({ orgId: "org-1", alertId: "alert-1", incidentId: undefined }),
    );
  });

  it("does not dispatch suppressed or deduplicated alerts", async () => {
    policies.push({
      id: "policy-1",
      orgId: "org-1",
      name: "Alert policy",
      triggerType: "alert_created",
      conditions: {},
      actions: [{ actionType: "notify", config: {} }],
      status: "active",
      confidenceThreshold: 0,
      cooldownMinutes: 0,
      maxActionsPerHour: 10,
      executionCount: 0,
    } as AutoResponsePolicy);

    await evaluateAndDispatchAlertPolicies(alert({ suppressed: true }));
    await evaluateAndDispatchAlertPolicies(alert({ status: "deduped" }));

    expect(dispatchAction).not.toHaveBeenCalled();
  });
});
