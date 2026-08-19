import { describe, expect, it } from "vitest";
import { getOrglessDestination } from "./org-routing";

describe("org-less routing", () => {
  it("sends a membership-less super-admin to platform administration", () => {
    expect(getOrglessDestination(true)).toBe("/platform-admin");
  });

  it("sends a membership-less non-super-admin to the terminal access state", () => {
    expect(getOrglessDestination(false)).toBe("/no-organization");
  });
});
