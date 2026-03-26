import { describe, it, expect, vi } from "vitest";

vi.mock("../db", () => ({
  pool: { query: vi.fn() },
}));

vi.mock("../config", () => ({
  config: { nodeEnv: "test" },
}));

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

vi.mock("../pagination-contract", () => ({
  PAGINATION_CONTRACT: {
    defaultLimit: 50,
    maxLimit: 200,
    defaultSortColumn: "createdAt",
    defaultSortOrder: "desc",
  },
  parseStandardPagination: (query: any) => ({
    offset: 0,
    limit: 50,
    sortOrder: "desc" as const,
  }),
}));

import { PERFORMANCE_BUDGETS } from "../db-performance";

describe("AI performance budgets", () => {
  it("defines budget for triage endpoint", () => {
    const budget = PERFORMANCE_BUDGETS["POST /api/ai/triage/:alertId"];
    expect(budget).toBeDefined();
    expect(budget.production).toBeLessThanOrEqual(2000);
  });

  it("defines budget for narrative endpoint", () => {
    const budget = PERFORMANCE_BUDGETS["POST /api/ai/narrative/:incidentId"];
    expect(budget).toBeDefined();
    expect(budget.production).toBeLessThanOrEqual(3000);
  });

  it("defines budget for correlate endpoint", () => {
    const budget = PERFORMANCE_BUDGETS["POST /api/ai/correlate"];
    expect(budget).toBeDefined();
    expect(budget.production).toBeLessThanOrEqual(3000);
  });

  it("defines budget for investigate endpoint", () => {
    const budget = PERFORMANCE_BUDGETS["POST /api/ai/investigate/:incidentId"];
    expect(budget).toBeDefined();
    expect(budget.production).toBeLessThanOrEqual(3000);
  });

  it("defines budget for triage job polling endpoint", () => {
    const budget = PERFORMANCE_BUDGETS["GET /api/ai/triage/jobs/:jobId"];
    expect(budget).toBeDefined();
    expect(budget.production).toBeLessThanOrEqual(500);
  });

  it("polling endpoint has stricter budget than triage endpoint", () => {
    const pollBudget = PERFORMANCE_BUDGETS["GET /api/ai/triage/jobs/:jobId"];
    const triageBudget = PERFORMANCE_BUDGETS["POST /api/ai/triage/:alertId"];
    expect(pollBudget.production).toBeLessThan(triageBudget.production);
  });
});
