import { describe, expect, it } from "vitest";
import { getOrglessDestination } from "./org-routing";

describe("org-less routing", () => {
  it("does not bounce a membership-less super-admin away from the requested route", () => {
    expect(getOrglessDestination(true)).toBeNull();
  });

  it("sends a membership-less non-super-admin to the terminal access state", () => {
    expect(getOrglessDestination(false)).toBe("/no-organization");
  });
});
