import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Express, Request, Response } from "express";

const mocks = vi.hoisted(() => ({
  getRuntimePolicies: vi.fn(),
  createRuntimeSimulation: vi.fn(),
  getRuntimeSimulations: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    getRuntimePolicies: mocks.getRuntimePolicies,
    createRuntimeSimulation: mocks.createRuntimeSimulation,
    getRuntimeSimulations: mocks.getRuntimeSimulations,
  },
}));

vi.mock("../routes/shared", () => ({
  getOrgId: vi.fn(() => "org-1"),
  logger: {
    child: () => ({
      error: vi.fn(),
    }),
  },
}));

vi.mock("../auth", () => ({ isAuthenticated: vi.fn() }));
vi.mock("../rbac", () => ({
  resolveOrgContext: vi.fn(),
  requireOrgId: vi.fn(),
  requireMinRole: vi.fn(() => vi.fn()),
}));

import { registerRuntimeGuardrailsRoutes } from "../routes/runtime-guardrails";

type RegisteredRoute = {
  method: string;
  path: string;
  handlers: Array<(request: Request, response: Response) => unknown>;
};

function registerRoutes(): RegisteredRoute[] {
  const routes: RegisteredRoute[] = [];
  const capture =
    (method: string) =>
    (path: string, ...handlers: Array<(request: Request, response: Response) => unknown>) => {
      routes.push({ method, path, handlers });
    };
  const app = {
    get: capture("GET"),
    post: capture("POST"),
    patch: capture("PATCH"),
    delete: capture("DELETE"),
  } as unknown as Express;
  registerRuntimeGuardrailsRoutes(app);
  return routes;
}

function responseMock(): Response {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

describe("runtime guardrail simulation persistence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getRuntimePolicies.mockResolvedValue([
      {
        id: "policy-1",
        orgId: "org-1",
        name: "Block shell",
        description: null,
        action: "shell_exec",
        scope: "global",
        mode: "enforce",
        conditions: [],
        priority: 100,
        enabled: true,
        metadata: { verdict: "deny" },
        createdAt: new Date("2026-01-01T00:00:00.000Z"),
        updatedAt: new Date("2026-01-01T00:00:00.000Z"),
      },
    ]);
    mocks.createRuntimeSimulation.mockResolvedValue({
      id: "simulation-1",
      orgId: "org-1",
      policyId: "policy-1",
      policyName: "Block shell",
      simulatedAction: "shell_exec",
      actualVerdict: "deny",
    });
  });

  it("persists a simulation generated from the tenant policy source", async () => {
    const route = registerRoutes().find(
      (candidate) => candidate.method === "POST" && candidate.path === "/api/runtime-guardrails/simulate",
    );
    const response = responseMock();

    await route?.handlers.at(-1)?.(
      { body: { policyId: "policy-1", action: "shell_exec", context: {} } } as Request,
      response,
    );

    expect(mocks.createRuntimeSimulation).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: "org-1",
        policyId: "policy-1",
        actualVerdict: "deny",
      }),
    );
    expect(response.json).toHaveBeenCalledWith(expect.objectContaining({ id: "simulation-1", orgId: "org-1" }));
  });

  it("reads simulation history from the tenant persistence method", async () => {
    mocks.getRuntimeSimulations.mockResolvedValue([{ id: "simulation-1", orgId: "org-1" }]);
    const route = registerRoutes().find(
      (candidate) => candidate.method === "GET" && candidate.path === "/api/runtime-guardrails/simulations",
    );
    const response = responseMock();

    await route?.handlers.at(-1)?.({} as Request, response);

    expect(mocks.getRuntimeSimulations).toHaveBeenCalledWith("org-1", 50);
    expect(response.json).toHaveBeenCalledWith([{ id: "simulation-1", orgId: "org-1" }]);
  });
});
