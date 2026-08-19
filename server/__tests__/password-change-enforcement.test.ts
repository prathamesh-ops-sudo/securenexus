import { describe, expect, it, vi } from "vitest";
import { passwordChangeRequiredMiddleware } from "../auth/password-change-enforcement";

function response() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
}

describe("password change enforcement", () => {
  it("blocks normal authenticated use until the password is changed", () => {
    const next = vi.fn();
    const res = response();

    passwordChangeRequiredMiddleware(
      {
        isAuthenticated: () => true,
        user: { passwordChangeRequired: true },
        path: "/api/dashboard",
        method: "GET",
      } as never,
      res as never,
      next,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        errors: [expect.objectContaining({ code: "PASSWORD_CHANGE_REQUIRED" })],
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("allows the change-password and logout escape hatches", () => {
    for (const path of ["/api/auth/change-password", "/api/logout", "/api/auth/me", "/api/auth/user"]) {
      const next = vi.fn();
      const res = response();
      passwordChangeRequiredMiddleware(
        {
          isAuthenticated: () => true,
          user: { passwordChangeRequired: true },
          path,
          method: path === "/api/logout" ? "POST" : "POST",
        } as never,
        res as never,
        next,
      );
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    }
  });

  it("does not block users who have completed the password change", () => {
    const next = vi.fn();
    passwordChangeRequiredMiddleware(
      {
        isAuthenticated: () => true,
        user: { passwordChangeRequired: false },
        path: "/api/dashboard",
        method: "GET",
      } as never,
      response() as never,
      next,
    );
    expect(next).toHaveBeenCalled();
  });
});
