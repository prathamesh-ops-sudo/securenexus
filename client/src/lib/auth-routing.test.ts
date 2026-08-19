import { describe, expect, it } from "vitest";
import { getAuthenticatedRouteDestination } from "./auth-routing";

describe("authenticated route handling", () => {
  it("redirects obsolete public authentication routes to the app root", () => {
    for (const path of ["/login", "/register", "/forgot-password?next=/", "/reset-password"]) {
      expect(getAuthenticatedRouteDestination(path)).toBe("/");
    }
  });

  it("leaves application routes unchanged", () => {
    expect(getAuthenticatedRouteDestination("/alerts")).toBeNull();
    expect(getAuthenticatedRouteDestination("/platform-admin")).toBeNull();
  });
});
