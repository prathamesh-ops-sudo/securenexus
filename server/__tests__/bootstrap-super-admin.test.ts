import { describe, expect, it, vi } from "vitest";

vi.mock("../db", () => ({ db: {} }));
vi.mock("../auth/storage", () => ({ authStorage: {} }));
vi.mock("../storage/audit", () => ({ createAuditLog: vi.fn() }));
vi.mock("../logger", () => ({
  logger: {
    child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
  },
}));

import {
  DEFAULT_SUPER_ADMIN_EMAIL,
  provisionPlatformSuperAdmin,
  validateBootstrapPassword,
} from "../bootstrap-super-admin";

const passwordHash = "hashed-password";

function buildDependencies(existingUser?: Record<string, unknown>) {
  return {
    getUserByEmail: vi.fn().mockResolvedValue(existingUser),
    upsertUser: vi.fn().mockImplementation(async (user) => ({
      id: "platform-user",
      ...user,
    })),
    createAuditLog: vi.fn().mockResolvedValue({ id: "audit-1" }),
  };
}

describe("platform super-admin bootstrap", () => {
  it("rejects a target email other than the platform owner", async () => {
    const dependencies = buildDependencies();

    await expect(
      provisionPlatformSuperAdmin(
        {
          email: "attacker@example.com",
          password: "StrongEnough1!",
          passwordHash,
        },
        dependencies,
      ),
    ).rejects.toThrow(`Bootstrap is restricted to ${DEFAULT_SUPER_ADMIN_EMAIL}`);

    expect(dependencies.getUserByEmail).not.toHaveBeenCalled();
    expect(dependencies.upsertUser).not.toHaveBeenCalled();
  });

  it("rejects a missing or weak password before touching storage", async () => {
    const dependencies = buildDependencies();

    await expect(
      provisionPlatformSuperAdmin({ email: DEFAULT_SUPER_ADMIN_EMAIL, password: "" }, dependencies),
    ).rejects.toThrow("SUPER_ADMIN_PASSWORD is required");
    await expect(
      provisionPlatformSuperAdmin({ email: DEFAULT_SUPER_ADMIN_EMAIL, password: "short" }, dependencies),
    ).rejects.toThrow("at least 8 characters");

    expect(dependencies.getUserByEmail).not.toHaveBeenCalled();
  });

  it("creates a super-admin account without creating an organization or membership", async () => {
    const dependencies = buildDependencies();

    const result = await provisionPlatformSuperAdmin(
      {
        email: DEFAULT_SUPER_ADMIN_EMAIL,
        password: "StrongEnough1!",
        passwordHash,
      },
      dependencies,
    );

    expect(result.action).toBe("created");
    expect(result.user.isSuperAdmin).toBe(true);
    expect(result.user.passwordChangeRequired).toBe(true);
    expect(dependencies.upsertUser).toHaveBeenCalledWith(
      expect.objectContaining({
        email: DEFAULT_SUPER_ADMIN_EMAIL,
        passwordHash,
        isSuperAdmin: true,
        passwordChangeRequired: true,
        passwordChangedAt: null,
      }),
    );
    expect(dependencies.upsertUser.mock.calls[0][0]).not.toHaveProperty("orgId");
    expect(dependencies.upsertUser.mock.calls[0][0]).not.toHaveProperty("membership");
    expect(dependencies.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "platform_super_admin_bootstrap",
        userId: "platform-user",
      }),
    );
  });

  it("repairs an existing account idempotently and preserves super-admin status", async () => {
    const existingUser = {
      id: "existing-user",
      email: DEFAULT_SUPER_ADMIN_EMAIL,
      isSuperAdmin: false,
      passwordChangeRequired: false,
      passwordHash: "old-hash",
      disabledAt: new Date(),
      lockedUntil: new Date(),
      failedLoginCount: 4,
    };
    const dependencies = buildDependencies(existingUser);

    const result = await provisionPlatformSuperAdmin(
      {
        email: DEFAULT_SUPER_ADMIN_EMAIL,
        password: "StrongEnough1!",
        passwordHash,
      },
      dependencies,
    );

    expect(result.action).toBe("repaired");
    expect(result.user.id).toBe("existing-user");
    expect(dependencies.upsertUser).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "existing-user",
        isSuperAdmin: true,
        passwordChangeRequired: true,
        passwordChangedAt: null,
        disabledAt: null,
        lockedUntil: null,
        failedLoginCount: 0,
      }),
    );
  });

  it("uses the existing password policy baseline", async () => {
    await expect(validateBootstrapPassword("short")).resolves.toEqual(["Password must be at least 8 characters"]);
    await expect(validateBootstrapPassword("eight888")).resolves.toEqual([]);
  });
});
