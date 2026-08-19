import { describe, expect, it } from "vitest";
import { filterNavItems, type SidebarNavItem } from "./sidebar-nav";

const items: SidebarNavItem[] = [
  { title: "Dashboard", url: "/" },
  { title: "Team", url: "/team" },
  { title: "Onboarding", url: "/onboarding" },
];

describe("sidebar navigation filtering", () => {
  it("does not apply analyst restrictions to super admins", () => {
    expect(filterNavItems(items, "super_admin")).toEqual(items);
  });

  it("retains analyst restrictions for analyst users", () => {
    expect(filterNavItems(items, "analyst")).toEqual([{ title: "Dashboard", url: "/" }]);
  });
});
