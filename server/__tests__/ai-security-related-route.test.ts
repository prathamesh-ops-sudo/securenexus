import { beforeEach, describe, expect, it, vi } from "vitest";

const { requiredRoles, listAiGuardEvents, getAlert, getIncident } = vi.hoisted(() => ({
  requiredRoles: [] as string[],
  listAiGuardEvents: vi.fn(),
  getAlert: vi.fn(),
  getIncident: vi.fn(),
}));

vi.mock("../auth", () => ({
  isAuthenticated: (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: (_req: unknown, _res: unknown, next: () => void) => next(),
  requireOrgId: (_req: unknown, _res: unknown, next: () => void) => next(),
  requireMinRole: (role: string) => {
    requiredRoles.push(role);
    return (_req: unknown, _res: unknown, next: () => void) => next();
  },
}));

vi.mock("../routes/shared", () => ({
  storage: { getAlert, getIncident },
  getOrgId: (req: { orgId: string }) => req.orgId,
}));

vi.mock("../ai/security-store", () => ({
  getAiSecuritySettings: vi.fn(),
  listAiGuardEvents,
  upsertAiSecuritySettings: vi.fn(),
}));

vi.mock("../ai/model-gateway", () => ({
  getModelPricing: vi.fn(() => ({})),
}));

vi.mock("../logger", () => ({
  logger: { child: () => ({ error: vi.fn(), warn: vi.fn() }) },
}));

vi.mock("../config", () => ({
  config: {
    ai: {
      modelId: "model",
      triage: { modelId: "triage-model" },
      investigation: { modelId: "investigation-model" },
    },
  },
}));

import { registerAiSecurityRoutes } from "../routes/ai-security";

type Handler = (req: any, res: any, next?: () => void) => Promise<unknown> | unknown;

function captureRoutes(): Map<string, Handler[]> {
  const routes = new Map<string, Handler[]>();
  const app = {
    get: (path: string, ...handlers: Handler[]) => routes.set(`GET ${path}`, handlers),
    put: (path: string, ...handlers: Handler[]) => routes.set(`PUT ${path}`, handlers),
  };
  registerAiSecurityRoutes(app as never);
  return routes;
}

function response() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
}

describe("relationship-scoped AI guard events", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    requiredRoles.length = 0;
  });

  it("registers a read-only member route separately from the analyst listing route", () => {
    const routes = captureRoutes();

    expect(routes.get("GET /api/ai/guard-events/related")).toHaveLength(5);
    expect(routes.get("GET /api/ai/guard-events")).toHaveLength(5);
    expect(requiredRoles).toEqual(["analyst", "read_only", "admin"]);
  });

  it("keeps relationship reads organization-scoped", async () => {
    const routes = captureRoutes();
    const handlers = routes.get("GET /api/ai/guard-events/related")!;
    getAlert.mockResolvedValue({ id: "11111111-1111-4111-8111-111111111111", orgId: "org-a" });

    const res = response();
    await handlers[4](
      {
        orgId: "org-b",
        query: { alertId: "11111111-1111-4111-8111-111111111111" },
      },
      res,
    );

    expect(res.status).toHaveBeenCalledWith(404);
    expect(listAiGuardEvents).not.toHaveBeenCalled();
  });

  it("returns only the requested relationship's events for a tenant member", async () => {
    const routes = captureRoutes();
    const handlers = routes.get("GET /api/ai/guard-events/related")!;
    const alertId = "11111111-1111-4111-8111-111111111111";
    getAlert.mockResolvedValue({ id: alertId, orgId: "org-a" });
    listAiGuardEvents.mockResolvedValue({ events: [{ id: "event-1" }], total: 1 });

    const res = response();
    await handlers[4]({ orgId: "org-a", query: { alertId } }, res);

    expect(listAiGuardEvents).toHaveBeenCalledWith({
      orgId: "org-a",
      page: 1,
      pageSize: 100,
      alertId,
      incidentId: undefined,
    });
    expect(res.json).toHaveBeenCalledWith({
      data: [{ id: "event-1" }],
      meta: { page: 1, pageSize: 100, total: 1, totalPages: 1 },
      errors: null,
    });
  });
});
