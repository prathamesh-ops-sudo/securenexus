import { describe, expect, it } from "vitest";
import { buildChangePasswordInput } from "@/lib/forced-password-change";

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
