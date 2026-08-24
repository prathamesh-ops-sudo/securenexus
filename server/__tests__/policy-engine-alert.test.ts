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
    countRecentPolicyActions: vi.fn(async () => 0),
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

  it("passes policy approval intent to the shared action dispatcher", async () => {
    policies.push({
      id: "policy-approval",
      orgId: "org-1",
      name: "Approval policy",
      triggerType: "alert_created",
      conditions: {},
      actions: [{ actionType: "isolate_host", config: { hostname: "host-1" } }],
      requiresApproval: true,
      status: "active",
      confidenceThreshold: 0,
      cooldownMinutes: 0,
      maxActionsPerHour: 10,
      executionCount: 0,
    } as AutoResponsePolicy);

    await evaluateAndDispatchAlertPolicies(alert());

    expect(dispatchAction).toHaveBeenCalledWith(
      "isolate_host",
      { hostname: "host-1" },
      expect.objectContaining({
        policyId: "policy-approval",
        requiresApproval: true,
        alertId: "alert-1",
        incidentId: undefined,
      }),
    );
  });

  it("uses trailing-hour persisted actions rather than lifetime execution count", async () => {
    const countRecentPolicyActions = vi.mocked((await import("../storage")).storage.countRecentPolicyActions);
    countRecentPolicyActions.mockResolvedValueOnce(0);
    policies.push({
      id: "policy-rate",
      orgId: "org-1",
      name: "Rate policy",
      triggerType: "alert_created",
      conditions: {},
      actions: [{ actionType: "notify", config: {} }],
      status: "active",
      confidenceThreshold: 0,
      cooldownMinutes: 0,
      maxActionsPerHour: 1,
      executionCount: 999,
    } as AutoResponsePolicy);

    const results = await evaluateAndDispatchAlertPolicies(alert());

    expect(results).toHaveLength(1);
    expect(countRecentPolicyActions).toHaveBeenCalledWith("org-1", "policy-rate", expect.any(Date));
  });

  it("withholds a policy when persisted executions reach the hourly limit", async () => {
    const countRecentPolicyActions = vi.mocked((await import("../storage")).storage.countRecentPolicyActions);
    countRecentPolicyActions.mockResolvedValueOnce(1);
    policies.push({
      id: "policy-rate-limited",
      orgId: "org-1",
      name: "Rate limited policy",
      triggerType: "alert_created",
      conditions: {},
      actions: [{ actionType: "notify", config: {} }],
      status: "active",
      confidenceThreshold: 0,
      cooldownMinutes: 0,
      maxActionsPerHour: 1,
      executionCount: 0,
    } as AutoResponsePolicy);

    const results = await evaluateAndDispatchAlertPolicies(alert());

    expect(results).toHaveLength(0);
    expect(dispatchAction).not.toHaveBeenCalled();
  });
});
