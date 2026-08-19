import { describe, expect, it } from "vitest";
import { WIZARD_STEPS } from "../schema";

describe("onboarding wizard step model", () => {
  it("starts with plan selection and excludes self-service organization creation", () => {
    expect(WIZARD_STEPS).toEqual(["choose_plan", "invite_team", "connect_integration", "dashboard_tour"]);
    expect(WIZARD_STEPS).not.toContain("create_org");
  });
});
