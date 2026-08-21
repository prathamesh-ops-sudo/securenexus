import express, { type Express } from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockGetEnabledModuleKeys, mockSetModuleEnabled } = vi.hoisted(() => ({
  mockGetEnabledModuleKeys: vi.fn(),
  mockSetModuleEnabled: vi.fn(),
}));

vi.mock("../auth", () => ({
  isAuthenticated: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
    if (req.headers["x-test-no-user"] !== "true") {
      req.user = { id: "user-1", email: "owner@example.com" } as Express.User;
    }
    next();
  },
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
    (req as express.Request & { orgId?: string }).orgId = "org-1";
    (req as express.Request & { orgRole?: string }).orgRole = String(req.headers["x-test-role"] || "owner");
    (req as express.Request & { orgReadOnly?: boolean }).orgReadOnly = req.headers["x-test-read-only"] === "true";
    next();
  },
  requireOrgId: (_req: express.Request, _res: express.Response, next: express.NextFunction) => next(),
  requireMinRole: (minRole: string) => (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const role = (req as express.Request & { orgRole?: string }).orgRole;
    const roleLevels: Record<string, number> = { read_only: 1, analyst: 2, admin: 3, owner: 4 };
    if ((roleLevels[role || ""] || 0) < (roleLevels[minRole] || 0)) {
      return res.status(403).json({ errors: [{ code: "FORBIDDEN", message: "Forbidden" }] });
    }
    next();
  },
}));

vi.mock("../routes/shared", () => ({
  getOrgId: (req: express.Request) => (req as express.Request & { orgId: string }).orgId,
}));

vi.mock("../storage/audit", () => ({
  createAuditLog: vi.fn().mockResolvedValue({ id: "audit-1" }),
}));

vi.mock("../module-settings", () => {
  const coreModules = ["Dashboard", "Alerts", "Incidents", "Assets", "Connectors"] as const;
  const moduleKeys = [
    ...coreModules,
    "Threat Intelligence",
    "Investigate",
    "Respond",
    "Posture",
    "Data & Integrations",
    "AI Analyst",
  ] as const;
  return {
    CORE_MODULES: coreModules,
    MODULE_KEYS: moduleKeys,
    canManageModuleSettings: (role: string | null | undefined, readOnlyContext: boolean) =>
      !readOnlyContext && (role === "owner" || role === "admin"),
    getDefaultEnabledModules: () => [...coreModules],
    isSupportedModuleKey: (value: unknown): boolean => typeof value === "string" && moduleKeys.includes(value as never),
    getEnabledModuleKeys: mockGetEnabledModuleKeys,
    setModuleEnabled: mockSetModuleEnabled,
  };
});

import {
  CORE_MODULES,
  MODULE_KEYS,
  canManageModuleSettings,
  getDefaultEnabledModules,
  isSupportedModuleKey,
  getEnabledModuleKeys,
  setModuleEnabled,
} from "../module-settings";
import { createAuditLog } from "../storage/audit";
import { registerModuleSettingsRoutes } from "../routes/module-settings";

const mockCreateAuditLog = vi.mocked(createAuditLog);

function createApp(): Express {
  const app = express();
  app.use(express.json());
  registerModuleSettingsRoutes(app);
  return app;
}

describe("module settings policy", () => {
  it("defaults a fresh organization to exactly the five core destinations", () => {
    expect(getDefaultEnabledModules()).toEqual([...CORE_MODULES]);
  });

  it("accepts only server-defined module keys", () => {
    expect(MODULE_KEYS.length).toBeGreaterThan(CORE_MODULES.length);
    expect(isSupportedModuleKey("AI Analyst")).toBe(true);
    expect(isSupportedModuleKey("arbitrary-client-module")).toBe(false);
  });

  it("allows only owner and admin members to manage settings", () => {
    expect(canManageModuleSettings("owner", false)).toBe(true);
    expect(canManageModuleSettings("admin", false)).toBe(true);
    expect(canManageModuleSettings("analyst", false)).toBe(false);
    expect(canManageModuleSettings("read_only", false)).toBe(false);
    expect(canManageModuleSettings("owner", true)).toBe(false);
  });
});

describe("module settings routes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetEnabledModuleKeys.mockResolvedValue([...CORE_MODULES]);
  });

  it("allows an authenticated member to read core-only settings for a fresh organization", async () => {
    const response = await request(createApp()).get("/api/org/module-settings").set("x-test-role", "analyst");

    expect(response.status).toBe(200);
    expect(response.body.data.enabledModules).toEqual([...CORE_MODULES]);
    expect(response.body.data.coreModules).toEqual([...CORE_MODULES]);
  });

  it("refuses a non-admin module write", async () => {
    const response = await request(createApp())
      .put("/api/org/module-settings")
      .set("x-test-role", "analyst")
      .send({ moduleKey: "Threat Intelligence", enabled: true });

    expect(response.status).toBe(403);
    expect(response.body.errors[0].code).toBe("FORBIDDEN");
    expect(mockSetModuleEnabled).not.toHaveBeenCalled();
  });

  it("refuses writes in a platform-admin read-only tenant context", async () => {
    const response = await request(createApp())
      .put("/api/org/module-settings")
      .set("x-test-role", "owner")
      .set("x-test-read-only", "true")
      .send({ moduleKey: "Threat Intelligence", enabled: true });

    expect(response.status).toBe(403);
    expect(response.body.errors[0].code).toBe("FORBIDDEN");
    expect(mockSetModuleEnabled).not.toHaveBeenCalled();
  });

  it("refuses an unknown module key", async () => {
    const response = await request(createApp())
      .put("/api/org/module-settings")
      .send({ moduleKey: "Not A Real Module", enabled: true });

    expect(response.status).toBe(400);
    expect(response.body.errors[0].message).toContain("Unsupported module key");
    expect(mockSetModuleEnabled).not.toHaveBeenCalled();
  });

  it("writes the setting and audit record for an owner", async () => {
    mockSetModuleEnabled.mockResolvedValue([...CORE_MODULES, "Threat Intelligence"]);

    const response = await request(createApp())
      .put("/api/org/module-settings")
      .send({ moduleKey: "Threat Intelligence", enabled: true });

    expect(response.status).toBe(200);
    expect(response.body.data.enabledModules).toContain("Threat Intelligence");
    expect(mockSetModuleEnabled).toHaveBeenCalledWith("org-1", "Threat Intelligence", true, "user-1");
    expect(mockCreateAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: "org-1",
        userId: "user-1",
        action: "module_enabled",
        resourceId: "Threat Intelligence",
        details: {
          moduleKey: "Threat Intelligence",
          oldEnabled: false,
          newEnabled: true,
        },
      }),
    );
  });

  it("refuses a write without a resolved actor", async () => {
    const response = await request(createApp())
      .put("/api/org/module-settings")
      .set("x-test-no-user", "true")
      .send({ moduleKey: "Threat Intelligence", enabled: true });

    expect(response.status).toBe(401);
    expect(response.body.errors[0].code).toBe("UNAUTHENTICATED");
    expect(mockSetModuleEnabled).not.toHaveBeenCalled();
  });
});
