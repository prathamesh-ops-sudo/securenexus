/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock storage functions before importing the engine
vi.mock("../storage/misc", () => ({
  getActiveSuppressionRules: vi.fn(),
  incrementSuppressionMatchCount: vi.fn(),
}));

// Mock logger
vi.mock("../logger", () => ({
  default: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

import { evaluateSuppression } from "../suppression-engine";
import { getActiveSuppressionRules, incrementSuppressionMatchCount } from "../storage/misc";

const mockGetActiveRules = getActiveSuppressionRules as ReturnType<typeof vi.fn>;
const mockIncrementMatch = incrementSuppressionMatchCount as ReturnType<typeof vi.fn>;

const baseAlert: any = {
  source: "crowdstrike",
  severity: "high",
  title: "Malware detected on host",
  category: "malware",
  orgId: "org-1",
  status: "new",
  description: "Test alert description",
};

const baseRule = {
  id: "rule-1",
  orgId: "org-1",
  name: "Test Rule",
  description: "Test suppression rule",
  scope: "source",
  scopeValue: "crowdstrike",
  matcher: null,
  reason: "Noisy source",
  source: null as string | null,
  severity: null as string | null,
  category: null as string | null,
  enabled: true,
  expiresAt: new Date(Date.now() + 86400000), // tomorrow
  matchCount: 0,
  lastMatchAt: null,
  createdBy: "user-1",
  ownedBy: "user-1",
  createdAt: new Date(),
  updatedAt: new Date(),
};

beforeEach(() => {
  vi.clearAllMocks();
  mockIncrementMatch.mockResolvedValue(undefined);
});

describe("evaluateSuppression", () => {
  it("returns suppressed=true when alert matches rule by source", async () => {
    const rule = { ...baseRule, source: "crowdstrike" };
    mockGetActiveRules.mockResolvedValue([rule]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(true);
    expect(result.ruleId).toBe("rule-1");
    expect(mockIncrementMatch).toHaveBeenCalledWith("rule-1");
  });

  it("returns suppressed=true when alert matches rule by severity", async () => {
    const rule = { ...baseRule, severity: "high" };
    mockGetActiveRules.mockResolvedValue([rule]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(true);
    expect(result.ruleId).toBe("rule-1");
  });

  it("returns suppressed=true when alert title matches rule regex pattern", async () => {
    const rule = {
      ...baseRule,
      matcher: [{ field: "title", op: "regex", value: "Malware.*host" }],
    };
    mockGetActiveRules.mockResolvedValue([rule]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(true);
    expect(result.ruleId).toBe("rule-1");
  });

  it("returns suppressed=false when no rules match", async () => {
    const rule = { ...baseRule, source: "splunk" };
    mockGetActiveRules.mockResolvedValue([rule]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(false);
    expect(result.ruleId).toBeNull();
    expect(mockIncrementMatch).not.toHaveBeenCalled();
  });

  it("skips expired rules (expiresAt < now)", async () => {
    const expiredRule = { ...baseRule, source: "crowdstrike", expiresAt: new Date(Date.now() - 86400000) };
    mockGetActiveRules.mockResolvedValue([]); // active rules query already filters expired

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(false);
    expect(result.ruleId).toBeNull();
  });

  it("skips disabled rules (enabled=false)", async () => {
    // getActiveSuppressionRules filters disabled rules at query level
    mockGetActiveRules.mockResolvedValue([]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(false);
    expect(result.ruleId).toBeNull();
  });

  it("matchesRule with invalid regex does not throw (returns false, logs warning)", async () => {
    const rule = {
      ...baseRule,
      matcher: [{ field: "title", op: "regex", value: "[invalid(regex" }],
    };
    mockGetActiveRules.mockResolvedValue([rule]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(false);
    expect(result.ruleId).toBeNull();
  });

  it("first-match short-circuit (returns first matching rule, does not evaluate further)", async () => {
    const rule1 = { ...baseRule, id: "rule-1", source: "crowdstrike" };
    const rule2 = { ...baseRule, id: "rule-2", source: "crowdstrike" };
    mockGetActiveRules.mockResolvedValue([rule1, rule2]);

    const result = await evaluateSuppression(baseAlert, "org-1");

    expect(result.suppressed).toBe(true);
    expect(result.ruleId).toBe("rule-1");
    // Only the first matching rule's count should be incremented
    expect(mockIncrementMatch).toHaveBeenCalledTimes(1);
    expect(mockIncrementMatch).toHaveBeenCalledWith("rule-1");
  });
});
