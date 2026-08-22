import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Express, Request, Response } from "express";

const mocks = vi.hoisted(() => ({
  createComplianceGapAssessment: vi.fn(),
  getComplianceGapAssessments: vi.fn(),
  getComplianceGapsByFramework: vi.fn(),
  getComplianceControls: vi.fn(),
  getComplianceControlMappings: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    createComplianceGapAssessment: mocks.createComplianceGapAssessment,
    getComplianceGapAssessments: mocks.getComplianceGapAssessments,
    getComplianceGapsByFramework: mocks.getComplianceGapsByFramework,
  },
}));

vi.mock("../storage/compliance", () => ({
  getComplianceControls: mocks.getComplianceControls,
  getComplianceControlMappings: mocks.getComplianceControlMappings,
}));

vi.mock("../routes/shared", () => ({
  getOrgId: vi.fn(() => "org-1"),
  storage: {
    createComplianceGapAssessment: mocks.createComplianceGapAssessment,
    getComplianceGapAssessments: mocks.getComplianceGapAssessments,
    getComplianceGapsByFramework: mocks.getComplianceGapsByFramework,
  },
  logger: {
    child: () => ({ info: vi.fn(), error: vi.fn() }),
  },
  reply: (res: Response, data: unknown, meta?: unknown, status = 200) =>
    res.status(status).json({ data, meta: meta || {}, errors: null }),
  replyError: (res: Response, status: number, errors: unknown) =>
    res.status(status).json({ data: null, meta: {}, errors }),
  sendEnvelope: vi.fn(),
}));

vi.mock("../auth", () => ({ isAuthenticated: vi.fn() }));
vi.mock("../rbac", () => ({
  resolveOrgContext: vi.fn(),
  requireMinRole: vi.fn(() => vi.fn()),
}));

import { registerComplianceGapRoutes } from "../routes/compliance-gap";

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
  registerComplianceGapRoutes(app);
  return routes;
}

function responseMock(): Response {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

describe("compliance gap persistence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getComplianceControls.mockResolvedValue([]);
    mocks.getComplianceControlMappings.mockResolvedValue([]);
    let sequence = 0;
    mocks.createComplianceGapAssessment.mockImplementation(async (data) => ({
      id: `assessment-${++sequence}`,
      ...data,
    }));
  });

  it("persists each assessed control and returns a persisted assessment id", async () => {
    const route = registerRoutes().find((candidate) => candidate.path === "/api/compliance-gap/analyze");
    const res = responseMock();

    await route?.handlers.at(-1)?.({ body: { framework: "soc2" } } as Request, res);

    expect(mocks.createComplianceGapAssessment).toHaveBeenCalled();
    expect(mocks.createComplianceGapAssessment.mock.calls[0][0]).toMatchObject({ orgId: "org-1" });
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ id: "assessment-1" }) }),
    );
  });
});
