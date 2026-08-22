import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Express, Request, Response } from "express";

const mocks = vi.hoisted(() => ({
  getCrossCuttingDriftRecords: vi.fn(),
  createCrossCuttingDriftRecord: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    getCrossCuttingDriftRecords: mocks.getCrossCuttingDriftRecords,
    createCrossCuttingDriftRecord: mocks.createCrossCuttingDriftRecord,
  },
}));

vi.mock("../storage/cross-cutting", () => ({
  getKillSwitchesList: vi.fn(),
  getKillSwitchById: vi.fn(),
  createKillSwitch: vi.fn(),
  updateKillSwitch: vi.fn(),
  countKillSwitches: vi.fn(),
  getTtvMilestones: vi.fn(),
  getTtvMilestoneByKind: vi.fn(),
  createTtvMilestone: vi.fn(),
  updateTtvMilestone: vi.fn(),
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
}));

vi.mock("../auth", () => ({
  isAuthenticated: vi.fn(),
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: vi.fn(),
  requireOrgId: vi.fn(),
  requireMinRole: vi.fn(() => vi.fn()),
}));

import { registerCrossCuttingRoutes } from "../routes/cross-cutting";

type RegisteredRoute = {
  path: string;
  handlers: Array<(...args: any[]) => unknown>;
};

function registerRoutes(): RegisteredRoute[] {
  const routes: RegisteredRoute[] = [];
  const capture = (path: string, ...handlers: Array<(...args: any[]) => unknown>) => {
    routes.push({ path, handlers });
  };
  const app = { get: capture, post: capture, put: capture, patch: capture, delete: capture } as unknown as Express;
  registerCrossCuttingRoutes(app);
  return routes;
}

function responseMock(): Response {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

describe("cross-cutting drift summary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.createCrossCuttingDriftRecord.mockResolvedValue({ id: "drift-1", status: "detected" });
  });

  it("counts detected rows returned from the tenant-scoped persisted read", async () => {
    mocks.getCrossCuttingDriftRecords.mockResolvedValue([
      { id: "drift-1", orgId: "org-1", status: "detected" },
      { id: "drift-2", orgId: "org-1", status: "resolved" },
    ]);
    const route = registerRoutes().find((candidate) => candidate.path === "/api/cross-cutting/drift/scan");
    expect(route).toBeDefined();
    const handler = route?.handlers.at(-1);
    const res = responseMock();

    await handler?.({ body: {} } as Request, res);

    expect(mocks.getCrossCuttingDriftRecords).toHaveBeenCalledWith("org-1");
    expect(res.json).toHaveBeenCalledWith({
      data: { scanId: "drift-1", status: "completed", driftsDetected: 1 },
      meta: {},
      errors: null,
    });
  });
});
