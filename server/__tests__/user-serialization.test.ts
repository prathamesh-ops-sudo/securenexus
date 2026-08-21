import { describe, expect, it } from "vitest";
import type { User } from "@shared/models/auth";
import { serializeUser } from "../auth/user-serialization";

describe("serializeUser", () => {
  it("returns only the allowlisted client-safe fields", () => {
    const user = {
      id: "user-1",
      email: "user@example.com",
      firstName: "Test",
      lastName: "User",
      profileImageUrl: null,
      isSuperAdmin: false,
      disabledAt: null,
      lastLoginAt: null,
      passwordChangedAt: null,
      passwordChangeRequired: true,
      lockedUntil: new Date("2026-01-01T00:00:00.000Z"),
      failedLoginCount: 4,
      passwordHash: "password-hash",
      mfaEnabled: true,
      mfaSecret: "totp-secret",
      mfaVerifiedAt: new Date("2026-01-01T00:00:00.000Z"),
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    } as User;

    const serialized = serializeUser(user, {
      orgId: "org-1",
      role: "owner",
      mfaRequired: true,
      passwordExpired: false,
    });

    expect(serialized).toMatchObject({
      id: "user-1",
      email: "user@example.com",
      isSuperAdmin: false,
      hasLocalPassword: true,
      orgId: "org-1",
      role: "owner",
      mfaRequired: true,
      passwordExpired: false,
    });
    expect(serialized).not.toHaveProperty("passwordHash");
    expect(serialized).not.toHaveProperty("mfaSecret");
    expect(serialized).not.toHaveProperty("failedLoginCount");
    expect(serialized).not.toHaveProperty("lockedUntil");
    expect(Object.keys(serialized)).toEqual([
      "id",
      "email",
      "firstName",
      "lastName",
      "profileImageUrl",
      "isSuperAdmin",
      "disabledAt",
      "lastLoginAt",
      "passwordChangedAt",
      "passwordChangeRequired",
      "mfaEnabled",
      "mfaVerifiedAt",
      "createdAt",
      "updatedAt",
      "hasLocalPassword",
      "orgId",
      "role",
      "mfaRequired",
      "passwordExpired",
    ]);
  });
});
