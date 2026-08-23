import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  execute: vi.fn(),
}));

vi.mock("../db", () => ({ db: { execute: mocks.execute } }));
vi.mock("../auth", () => ({ isAuthenticated: (_req: any, _res: any, next: any) => next() }));
vi.mock("../rbac", () => ({
  resolveOrgContext: (req: any, _res: any, next: any) => {
    req.orgId = "org-1";
    next();
  },
  requireOrgId: (_req: any, _res: any, next: any) => next(),
  requireMinRole: () => (_req: any, _res: any, next: any) => next(),
}));
vi.mock("../logger", () => ({
  logger: { child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }) },
}));
vi.mock("../ai/autonomous-analyst", () => ({
  triageAlert: vi.fn(),
  overrideDecision: vi.fn(),
  approveDecision: vi.fn(),
  getAutonomousSOCStats: vi.fn(),
}));
vi.mock("../ai/decision-receipts", () => ({ getDecisionReceipt: vi.fn() }));

import express from "express";
import request from "supertest";
import { registerAutonomousSocRoutes } from "../routes/autonomous-soc";

describe("autonomous SOC performance metrics", () => {
  it("returns persisted performance data without querying a nonexistent override column", async () => {
    mocks.execute.mockResolvedValueOnce({
      rows: [
        {
          total_decisions: "2",
          tier1_count: "1",
          fn_count: "0",
          escalation_count: "1",
          override_count: "1",
          avg_time_ms: 250,
          avg_confidence: 0.8,
        },
      ],
    });

    const app = express();
    registerAutonomousSocRoutes(app);
    const response = await request(app).get("/api/autonomous-soc/performance-metrics");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      alertsPerHour: 0,
      falseNegativeRate: 0,
      escalationPercentage: 50,
      overridePercentage: 50,
      timeSavedMinutes: 15,
      avgDecisionTimeMs: 250,
      avgConfidence: 0.8,
    });
  });
});
