import { describe, expect, it } from "vitest";
import { getInitialPlatformAdminOrgId } from "./use-org-context";

describe("getInitialPlatformAdminOrgId", () => {
  it("selects the first available organization for a platform admin without a selection", () => {
    expect(getInitialPlatformAdminOrgId(null, true, [{ id: "org-first" }, { id: "org-second" }])).toBe("org-first");
  });

  it("preserves an existing selection and leaves non-admin users unchanged", () => {
    expect(getInitialPlatformAdminOrgId("org-selected", true, [{ id: "org-first" }])).toBe("org-selected");
    expect(getInitialPlatformAdminOrgId(null, false, [{ id: "org-first" }])).toBeNull();
  });
});
