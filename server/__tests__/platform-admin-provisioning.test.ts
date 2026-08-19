import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  transaction: vi.fn(),
  createAuditLog: vi.fn().mockResolvedValue({}),
  sendEmail: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../db", () => ({
  db: { transaction: mocks.transaction },
  pool: {},
  getPoolHealth: vi.fn(),
  checkPoolConnectivity: vi.fn(),
}));
vi.mock("../routes/shared", () => ({
  sendEnvelope: vi.fn((res: any, data: unknown, options?: { status?: number }) => {
    res.status(options?.status ?? 200).json({ data });
    return res;
  }),
  storage: { createAuditLog: mocks.createAuditLog },
  logger: { child: () => ({ error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() }) },
}));
vi.mock("../auth", () => ({ isAuthenticated: (_req: unknown, _res: unknown, next: () => void) => next() }));
vi.mock("../middleware/super-admin", () => ({
  requireSuperAdmin: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
vi.mock("../auth/session", () => ({ invalidateDeserializeCache: vi.fn() }));
vi.mock("../auth/storage", () => ({ authStorage: {} }));
vi.mock("../email-service", () => ({ sendEmail: mocks.sendEmail }));
vi.mock("../email-templates", () => ({
  passwordResetEmail: vi.fn(() => ({ subject: "Set password", html: "<p>Set password</p>", text: "Set password" })),
  welcomeEmail: vi.fn(() => ({ subject: "Welcome", html: "<p>Welcome</p>", text: "Welcome" })),
}));
vi.mock("../middleware/auth-rate-limit", () => ({
  getLockedAccounts: vi.fn(),
  adminUnlockAccount: vi.fn(),
  getFailedLoginHistory: vi.fn(),
  getFailedLoginStats: vi.fn(),
}));
vi.mock("../logger", () => ({ logger: { child: () => ({ error: vi.fn(), warn: vi.fn(), info: vi.fn() }) } }));

import { getRequiredAppBaseUrl, registerPlatformAdminRoutes } from "../routes/platform-admin";

type Handler = (req: any, res: any, next?: () => void) => Promise<unknown> | unknown;

function captureTenantRoute(): Handler[] {
  let handlers: Handler[] = [];
  const app = {
    get: () => undefined,
    post: (path: string, ...routeHandlers: Handler[]) => {
      if (path === "/api/platform-admin/tenants") handlers = routeHandlers;
    },
    patch: () => undefined,
    put: () => undefined,
    delete: () => undefined,
  };
  registerPlatformAdminRoutes(app as never);
  return handlers;
}

function response() {
  return { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
}

describe("platform tenant provisioning", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.APP_BASE_URL = "https://local.example.test";
  });

  it("requires APP_BASE_URL before beginning provisioning", () => {
    delete process.env.APP_BASE_URL;
    expect(() => getRequiredAppBaseUrl()).toThrow("APP_BASE_URL is required");
  });

  it("uses the transaction executor for organization, user, membership, and set-password token writes", async () => {
    const org = { id: "org-1", name: "Tenant One" };
    const user = {
      id: "user-1",
      email: "owner@example.com",
      passwordHash: null,
      firstName: "Owner",
      lastName: "One",
    };
    let insertCount = 0;
    const tx = {
      insert: vi.fn(() => {
        insertCount += 1;
        return {
          values: vi.fn(() => ({
            returning: vi.fn().mockResolvedValue(insertCount === 1 ? [org] : insertCount === 2 ? [user] : []),
          })),
        };
      }),
      select: vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            limit: vi.fn().mockResolvedValue([]),
          })),
        })),
      })),
    };
    mocks.transaction.mockImplementation(async (callback: (value: typeof tx) => Promise<unknown>) => callback(tx));

    const handlers = captureTenantRoute();
    const res = response();
    await handlers[2](
      {
        user: { id: "admin-1", email: "admin@example.com" },
        body: {
          orgName: "Tenant One",
          adminEmail: "owner@example.com",
          adminFirstName: "Owner",
          adminLastName: "One",
        },
      },
      res,
    );

    expect(mocks.transaction).toHaveBeenCalledTimes(1);
    expect(tx.insert).toHaveBeenCalledTimes(4);
    expect(mocks.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: "platform_admin_tenant_created" }),
    );
    expect(mocks.sendEmail).toHaveBeenCalledTimes(1);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          adminUser: expect.objectContaining({ setPasswordUrl: expect.stringContaining("/reset-password?token=") }),
        }),
      }),
    );
  });
});
