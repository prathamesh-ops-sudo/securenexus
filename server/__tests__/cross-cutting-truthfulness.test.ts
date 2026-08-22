import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Express, Request, Response } from "express";

const mocks = vi.hoisted(() => ({
  getCrossCuttingDriftRecords: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    getCrossCuttingDriftRecords: mocks.getCrossCuttingDriftRecords,
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
  });

  it("reports that scanning is unavailable without creating synthetic drift evidence", async () => {
    const route = registerRoutes().find((candidate) => candidate.path === "/api/cross-cutting/drift/scan");
    expect(route).toBeDefined();
    const handler = route?.handlers.at(-1);
    const res = responseMock();

    await handler?.({ body: {} } as Request, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith({
      data: {
        status: "unavailable",
        message: "Drift scanning is unavailable because no persisted baseline comparison engine is configured.",
      },
      meta: {},
      errors: null,
    });
    expect(mocks.getCrossCuttingDriftRecords).not.toHaveBeenCalled();
  });
});
