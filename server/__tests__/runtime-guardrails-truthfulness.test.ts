import { describe, expect, it } from "vitest";
import { evaluateAction, getPolicies, toPolicyRule, type PolicyAction } from "../runtime-guardrails-engine";
import type { RuntimeGuardrailPolicy } from "@shared/schema";

function persistedPolicy(overrides: Partial<RuntimeGuardrailPolicy> = {}): RuntimeGuardrailPolicy {
  return {
    id: "tenant-policy-1",
    orgId: "org-1",
    name: "Block shell execution",
    description: "",
    action: "shell_exec",
    scope: "global",
    mode: "enforce",
    conditions: [],
    priority: 100,
    enabled: true,
    metadata: { actions: ["shell_exec" satisfies PolicyAction], verdict: "deny" },
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

describe("runtime guardrail policy provenance", () => {
  it("evaluates only the persisted tenant policy source", () => {
    const policy = toPolicyRule(persistedPolicy());
    const decision = evaluateAction(
      "org-1",
      {
        action: "shell_exec",
        actorId: "actor-1",
        actorType: "agent",
        resourceId: "resource-1",
        resourceType: "command",
        context: {},
      },
      { skipLog: true },
      [policy],
    );

    expect(decision).toMatchObject({
      orgId: "org-1",
      policyId: "tenant-policy-1",
      policyName: "Block shell execution",
      verdict: "deny",
    });
  });

  it("does not expose catalog policies through the engine policy list", () => {
    expect(getPolicies("org-without-policies")).toEqual([]);
  });
});
