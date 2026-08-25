import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  transaction: vi.fn(),
  select: vi.fn(),
  createAuditLog: vi.fn().mockResolvedValue({}),
  replacePasswordResetToken: vi.fn().mockResolvedValue({}),
  sendEmailWithStatus: vi.fn().mockResolvedValue({ accepted: true, status: "accepted" }),
}));

vi.mock("../db", () => ({
  db: { transaction: mocks.transaction, select: mocks.select },
  pool: {},
  getPoolHealth: vi.fn(),
  checkPoolConnectivity: vi.fn(),
}));
vi.mock("../routes/shared", () => ({
  sendEnvelope: vi.fn(
    (
      res: { status: (status: number) => { json: (body: unknown) => unknown } },
      data: unknown,
      options?: { status?: number; errors?: unknown[] },
    ) => {
      res.status(options?.status ?? 200).json({ data, errors: options?.errors ?? [] });
    },
  ),
  storage: {
    createAuditLog: mocks.createAuditLog,
    replacePasswordResetToken: mocks.replacePasswordResetToken,
  },
  logger: { child: () => ({ error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() }) },
}));
vi.mock("../auth", () => ({ isAuthenticated: (_req: unknown, _res: unknown, next: () => void) => next() }));
vi.mock("../middleware/super-admin", () => ({
  requireSuperAdmin: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
vi.mock("../auth/session", () => ({ invalidateDeserializeCache: vi.fn() }));
vi.mock("../auth/storage", () => ({ authStorage: {} }));
vi.mock("../email-service", () => ({ sendEmailWithStatus: mocks.sendEmailWithStatus }));
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

interface TestRequest {
  user?: { id: string; email: string };
  body: Record<string, unknown>;
  params?: Record<string, string>;
}

interface TestResponse {
  status: (status: number) => TestResponse;
  json: (body: unknown) => TestResponse;
}

type Handler = (req: TestRequest, res: TestResponse, next?: () => void) => Promise<unknown> | unknown;

function captureRoute(targetPath: string): Handler[] {
  let handlers: Handler[] = [];
  const app = {
    get: () => undefined,
    post: (path: string, ...routeHandlers: Handler[]) => {
      if (path === targetPath) handlers = routeHandlers;
    },
    patch: () => undefined,
    put: () => undefined,
    delete: () => undefined,
  };
  registerPlatformAdminRoutes(app as never);
  return handlers;
}

function response() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as TestResponse & {
    status: ReturnType<typeof vi.fn>;
    json: ReturnType<typeof vi.fn>;
  };
}

function setupProvisioningTransaction() {
  const org = { id: "org-1", name: "Tenant One" };
  const user = {
    id: "user-1",
    email: "owner@example.com",
    passwordHash: null,
    mfaSecret: "encrypted-totp-secret",
    failedLoginCount: 3,
    lockedUntil: new Date("2026-01-01T00:00:00.000Z"),
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
  return tx;
}

async function invokeProvisioning(): Promise<ReturnType<typeof response>> {
  const handlers = captureRoute("/api/platform-admin/tenants");
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
  return res;
}

describe("platform tenant provisioning", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.APP_BASE_URL = "https://local.example.test";
    process.env.NODE_ENV = "development";
    mocks.select.mockReset();
    mocks.replacePasswordResetToken.mockClear();
  });

  it("requires APP_BASE_URL before beginning provisioning", () => {
    delete process.env.APP_BASE_URL;
    expect(() => getRequiredAppBaseUrl()).toThrow("APP_BASE_URL is required");
  });

  it("uses the transaction executor for organization, user, membership, and set-password token writes", async () => {
    const tx = setupProvisioningTransaction();
    const res = await invokeProvisioning();

    expect(mocks.transaction).toHaveBeenCalledTimes(1);
    expect(tx.insert).toHaveBeenCalledTimes(4);
    expect(mocks.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: "platform_admin_tenant_created" }),
    );
    expect(mocks.sendEmailWithStatus).toHaveBeenCalledTimes(1);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          adminUser: expect.objectContaining({ setPasswordUrl: expect.stringContaining("/reset-password?token=") }),
          emailDelivery: { accepted: true, status: "accepted" },
        }),
      }),
    );
    const responseBody = (res.json as unknown as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[0];
    expect(responseBody.data.adminUser).not.toHaveProperty("passwordHash");
    expect(responseBody.data.adminUser).not.toHaveProperty("mfaSecret");
    expect(responseBody.data.adminUser).not.toHaveProperty("failedLoginCount");
    expect(responseBody.data.adminUser).not.toHaveProperty("lockedUntil");
  });

  it.each([
    {
      name: "not attempted when email delivery is disabled",
      delivery: { accepted: false, status: "not_attempted" as const },
    },
    {
      name: "failed when the provider rejects delivery",
      delivery: { accepted: false, status: "failed" as const },
    },
  ])("$name", async ({ delivery }) => {
    mocks.sendEmailWithStatus.mockResolvedValue(delivery);
    setupProvisioningTransaction();
    const res = await invokeProvisioning();

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          emailDelivery: delivery,
        }),
      }),
    );
  });

  it("refuses destructive platform seeding outside development", async () => {
    process.env.NODE_ENV = "production";
    const handlers = captureRoute("/api/platform-admin/seed-platform");
    const res = response();

    await handlers[2]({ user: { id: "admin-1", email: "admin@example.com" }, body: {} }, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        errors: [expect.objectContaining({ code: "DEVELOPMENT_ONLY" })],
      }),
    );
    expect(mocks.transaction).not.toHaveBeenCalled();
  });

  it("issues an audited, short-lived one-time reset link and invalidates prior links", async () => {
    const target = {
      id: "user-2",
      email: "owner@tenant.example",
      isSuperAdmin: false,
      passwordHash: "existing-hash",
    };
    const limit = vi.fn().mockResolvedValue([target]);
    mocks.select.mockReturnValue({
      from: vi.fn(() => ({
        where: vi.fn(() => ({ limit })),
      })),
    });
    const handlers = captureRoute("/api/platform-admin/users/:id/password-reset-link");
    const res = response();

    await handlers[2](
      {
        user: { id: "admin-1", email: "admin@example.com" },
        body: {},
        params: { id: target.id },
      },
      res,
    );

    expect(mocks.replacePasswordResetToken).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: target.id,
        token: expect.stringMatching(/^[a-f0-9]{64}$/),
        expiresAt: expect.any(Date),
      }),
    );
    expect(mocks.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "admin-1",
        action: "platform_admin_password_reset_link_issued",
        resourceId: target.id,
        details: expect.objectContaining({
          targetEmail: target.email,
          issuedAt: expect.any(String),
          expiresAt: expect.any(String),
          expiresInMinutes: 15,
        }),
      }),
    );
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          resetUrl: expect.stringMatching(/^https:\/\/local\.example\.test\/reset-password\?token=/),
          expiresAt: expect.any(String),
          expiresInMinutes: 15,
        }),
      }),
    );
  });
});
