import { describe, expect, it } from "vitest";
import { getAuthenticatedRouteDestination, hasPasswordResetToken, isPasswordRecoveryRoute } from "./auth-routing";

describe("authenticated route handling", () => {
  it("redirects obsolete public authentication routes to the app root", () => {
    for (const path of ["/login", "/register", "/reset-password"]) {
      expect(getAuthenticatedRouteDestination(path)).toBe("/");
    }
  });

  it("allows authenticated recovery routes to render", () => {
    expect(getAuthenticatedRouteDestination("/forgot-password")).toBeNull();
    expect(getAuthenticatedRouteDestination("/reset-password?token=valid-token")).toBeNull();
    expect(hasPasswordResetToken("/reset-password?token=valid-token")).toBe(true);
    expect(isPasswordRecoveryRoute("/forgot-password")).toBe(true);
    expect(isPasswordRecoveryRoute("/reset-password?token=valid-token")).toBe(true);
    expect(isPasswordRecoveryRoute("/reset-password")).toBe(false);
  });

  it("leaves application routes unchanged", () => {
    expect(getAuthenticatedRouteDestination("/alerts")).toBeNull();
    expect(getAuthenticatedRouteDestination("/platform-admin")).toBeNull();
  });
});
