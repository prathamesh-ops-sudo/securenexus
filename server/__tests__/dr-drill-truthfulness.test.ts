import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Express, Request, Response } from "express";

const mocks = vi.hoisted(() => ({
  createDrDrillResult: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    createDrDrillResult: mocks.createDrDrillResult,
  },
}));

vi.mock("../db", () => ({
  db: {},
}));

vi.mock("../routes/shared", () => ({
  getOrgId: vi.fn(() => "org-1"),
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
  sendEnvelope: vi.fn(),
  storage: {
    createDrDrillResult: mocks.createDrDrillResult,
  },
}));

vi.mock("../auth", () => ({
  isAuthenticated: vi.fn(),
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: vi.fn(),
  requireOrgId: vi.fn(),
  requireMinRole: vi.fn(() => vi.fn()),
}));

vi.mock("../data-lifecycle", () => ({
  getRetentionPolicies: vi.fn(),
  getLifecycleStatus: vi.fn(),
  executeDeletion: vi.fn(),
}));

vi.mock("../job-queue", () => ({
  getWorkerStatus: vi.fn(),
  retryDeadLetterJob: vi.fn(),
}));

import { registerPhase2FeatureRoutes } from "../routes/phase2-features";

type RegisteredRoute = {
  method: string;
  path: string;
  handlers: Array<(...args: any[]) => unknown>;
};

function registerRoutes(): RegisteredRoute[] {
  const routes: RegisteredRoute[] = [];
  const capture =
    (method: string) =>
    (path: string, ...handlers: Array<(...args: any[]) => unknown>) => {
      routes.push({ method, path, handlers });
    };
  const app = {
    get: capture("GET"),
    post: capture("POST"),
    put: capture("PUT"),
    patch: capture("PATCH"),
    delete: capture("DELETE"),
  } as unknown as Express;
  registerPhase2FeatureRoutes(app);
  return routes;
}

function responseMock(): Response {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

describe("DR drill request truthfulness", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.createDrDrillResult.mockResolvedValue({
      id: "drill-1",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
  });

  it("persists a pending request without execution measurements or a favorable result", async () => {
    const route = registerRoutes().find(
      (candidate) => candidate.method === "POST" && candidate.path === "/api/dr-drills",
    );
    expect(route).toBeDefined();
    const handler = route?.handlers.at(-1);
    const res = responseMock();

    await handler?.({ body: { type: "failover", name: "Requested failover drill" } } as Request, res);

    expect(mocks.createDrDrillResult).toHaveBeenCalledWith({
      orgId: "org-1",
      dryRun: null,
      status: "pending",
      triggeredBy: "manual",
      notes: "Requested failover drill",
      startedAt: null,
    });
    expect(res.json).toHaveBeenCalledWith({
      id: "drill-1",
      name: "Requested failover drill",
      type: "failover",
      status: "pending",
      scheduledAt: "2026-01-01T00:00:00.000Z",
      findings: [],
    });
    expect(JSON.stringify(res.json.mock.calls[0][0])).not.toContain("passed");
  });
});
