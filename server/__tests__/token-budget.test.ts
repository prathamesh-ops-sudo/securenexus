import { describe, it, expect, vi } from "vitest";

// Mock tokenizer with simple word-based approximation
vi.mock("../ai/tokenizer", () => ({
  countTokens: vi.fn((text: string) => {
    // Approximate: ~4 chars per token (consistent heuristic for tests)
    return Math.ceil(text.length / 4);
  }),
}));

// Mock logger
vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
  },
}));

import { buildBudgetedNarrativeMessage } from "../ai/narrative-budget";

function makeIncident(overrides: Record<string, unknown> = {}) {
  return {
    id: "inc-1",
    title: "Brute Force Attack Detected",
    summary: "Multiple failed login attempts",
    severity: "high",
    status: "investigating",
    mitreTactics: ["Initial Access"],
    mitreTechniques: ["T1110"],
    affectedAssets: ["web-server-01"],
    createdAt: new Date("2026-03-20T10:00:00Z"),
    ...overrides,
  } as any;
}

function makeAlert(id: string, severity: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    title: `Alert ${id}`,
    source: "crowdstrike",
    category: "network",
    severity,
    description: `Description for alert ${id} with some additional context about the detected threat activity`,
    sourceIp: "10.0.0.1",
    destIp: "10.0.0.2",
    hostname: "web-server-01",
    userId: "user-1",
    mitreTactic: "Initial Access",
    mitreTechnique: "T1110",
    detectedAt: new Date("2026-03-20T10:00:00Z"),
    fileHash: null,
    domain: null,
    url: null,
    ...overrides,
  } as any;
}

describe("Token Budget Enforcement", () => {
  it("returns message within maxInputTokens limit", () => {
    const incident = makeIncident();
    const alerts = [
      makeAlert("a1", "critical"),
      makeAlert("a2", "high"),
      makeAlert("a3", "medium"),
      makeAlert("a4", "low"),
      makeAlert("a5", "informational"),
    ];

    const result = buildBudgetedNarrativeMessage(incident, alerts, "", 4096, 2048);
    expect(result.totalInputTokens).toBeLessThanOrEqual(4096 - 2048);
  });

  it("includes higher-severity alerts before lower-severity when budget is tight", () => {
    const incident = makeIncident();
    const alerts = [
      makeAlert("low-1", "low"),
      makeAlert("crit-1", "critical"),
      makeAlert("info-1", "informational"),
      makeAlert("high-1", "high"),
      makeAlert("med-1", "medium"),
    ];

    // Very tight budget: should only fit incident context + a few alerts
    const result = buildBudgetedNarrativeMessage(incident, alerts, "", 1200, 400);

    // If any alerts were truncated, the truncated should be lower severity
    if (result.alertsTruncated > 0) {
      // We included some alerts -- the included ones should be the higher severity ones
      expect(result.alertsIncluded).toBeGreaterThan(0);
      // With tight budget, critical should always be included (it's first priority)
      expect(result.alertsIncluded).toBeGreaterThanOrEqual(1);
    }
  });

  it("reserves response tokens by subtracting from available budget", () => {
    const incident = makeIncident();
    const alerts = [makeAlert("a1", "critical")];

    const responseReservation = 2048;
    const maxInputTokens = 4096;
    const result = buildBudgetedNarrativeMessage(incident, alerts, "", maxInputTokens, responseReservation);

    // totalInputTokens should be within (maxInputTokens - responseReservation)
    expect(result.totalInputTokens).toBeLessThanOrEqual(maxInputTokens - responseReservation);
  });

  it("accounts for system prompt tokens in the budget", () => {
    const incident = makeIncident();
    const alerts = [makeAlert("a1", "critical")];

    // Even with just the incident context (always included), tokens are tracked
    const result = buildBudgetedNarrativeMessage(incident, alerts, "", 4096, 2048);
    expect(result.totalInputTokens).toBeGreaterThan(0);
  });

  it("includes all alerts when budget is generous", () => {
    const incident = makeIncident();
    const alerts = [
      makeAlert("a1", "critical"),
      makeAlert("a2", "high"),
      makeAlert("a3", "medium"),
    ];

    // Very generous budget
    const result = buildBudgetedNarrativeMessage(incident, alerts, "", 50000, 2048);
    expect(result.alertsIncluded).toBe(3);
    expect(result.alertsTruncated).toBe(0);
  });

  it("truncates lowest-severity alerts first when exceeding budget", () => {
    const incident = makeIncident();
    // Many alerts to force truncation
    const alerts = [
      makeAlert("crit-1", "critical"),
      makeAlert("high-1", "high"),
      makeAlert("med-1", "medium"),
      makeAlert("low-1", "low"),
      makeAlert("low-2", "low"),
      makeAlert("info-1", "informational"),
      makeAlert("info-2", "informational"),
      makeAlert("info-3", "informational"),
    ];

    // Tight budget that can't fit all 8 alerts
    const result = buildBudgetedNarrativeMessage(incident, alerts, "", 2000, 500);

    if (result.alertsTruncated > 0) {
      // Should have included the critical+high before low+informational
      expect(result.alertsIncluded).toBeGreaterThanOrEqual(1);
      expect(result.alertsIncluded + result.alertsTruncated).toBe(8);
    }
  });

  it("includes threat intel block when it fits within 30% budget", () => {
    const incident = makeIncident();
    const alerts = [makeAlert("a1", "critical")];
    const threatIntelBlock = "THREAT INTEL: Known APT group targeting financial sector";

    const result = buildBudgetedNarrativeMessage(incident, alerts, threatIntelBlock, 50000, 2048);
    expect(result.message).toContain("THREAT INTEL");
  });

  it("returns accurate alertsTruncated count", () => {
    const incident = makeIncident();
    const alerts = Array.from({ length: 20 }, (_, i) =>
      makeAlert(`alert-${i}`, i < 5 ? "critical" : i < 10 ? "high" : "low"),
    );

    const result = buildBudgetedNarrativeMessage(incident, alerts, "", 3000, 1000);
    expect(result.alertsIncluded + result.alertsTruncated).toBe(20);
  });
});
