import { describe, expect, it } from "vitest";
import type { AuthenticatedUser } from "@shared/models/auth";
import {
  buildChangePasswordInput,
  resolveForcedPasswordChangeAccountState,
  resolveLocalPasswordState,
} from "@/lib/forced-password-change";

const user = (hasLocalPassword: boolean): AuthenticatedUser => ({ hasLocalPassword }) as AuthenticatedUser;

describe("forced password-change account state", () => {
  it("distinguishes a failed account-state lookup from loading", () => {
    expect(
      resolveForcedPasswordChangeAccountState({
        user: undefined,
        isLoading: true,
        isError: false,
      }),
    ).toBe("loading");
    expect(
      resolveForcedPasswordChangeAccountState({
        user: undefined,
        isLoading: false,
        isError: true,
      }),
    ).toBe("error");
  });

  it("keeps loading state unknown", () => {
    expect(resolveLocalPasswordState({ user: undefined, isLoading: true, isError: false })).toBeUndefined();
  });

  it("keeps errored state unknown even when stale user data exists", () => {
    expect(resolveLocalPasswordState({ user: user(true), isLoading: false, isError: true })).toBeUndefined();
  });

  it("resolves the server-provided local-password state", () => {
    expect(resolveLocalPasswordState({ user: user(false), isLoading: false, isError: false })).toBe(false);
    expect(resolveLocalPasswordState({ user: user(true), isLoading: false, isError: false })).toBe(true);
  });
});

describe("forced password-change request payload", () => {
  it("omits current password for an account without a local password", () => {
    expect(
      buildChangePasswordInput({
        currentPassword: "",
        newPassword: "new-password-123",
        hasLocalPassword: false,
      }),
    ).toEqual({ newPassword: "new-password-123" });
  });

  it("preserves the current password when a local password exists", () => {
    expect(
      buildChangePasswordInput({
        currentPassword: "old-password-123",
        newPassword: "new-password-123",
        hasLocalPassword: true,
      }),
    ).toEqual({
      currentPassword: "old-password-123",
      newPassword: "new-password-123",
    });
  });

  it("omits an untouched current password instead of sending an empty value", () => {
    expect(
      buildChangePasswordInput({
        currentPassword: "",
        newPassword: "new-password-123",
        hasLocalPassword: true,
      }),
    ).toEqual({ newPassword: "new-password-123" });
  });
});
