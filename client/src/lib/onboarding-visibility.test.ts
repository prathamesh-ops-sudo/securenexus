import { describe, expect, it } from "vitest";
import { shouldShowOnboardingChecklist } from "./onboarding-visibility";

describe("onboarding surface visibility", () => {
  it("suppresses the floating checklist on the dashboard", () => {
    expect(shouldShowOnboardingChecklist("/")).toBe(false);
  });

  it("allows the floating checklist on non-dashboard routes", () => {
    expect(shouldShowOnboardingChecklist("/alerts")).toBe(true);
  });
});
