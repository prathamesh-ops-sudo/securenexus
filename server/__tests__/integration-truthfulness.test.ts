import { describe, expect, it, vi } from "vitest";
import { validateControllerConfiguration } from "../integrations/lenel";

describe("integration truthfulness", () => {
  it("reports controller configuration validity without claiming reachability", async () => {
    const result = await validateControllerConfiguration({
      type: "lenel",
      name: "Test controller",
      apiEndpoint: "https://controller.invalid/api",
      isActive: true,
    });

    expect(result).toEqual({
      status: "configuration_valid",
      message: expect.stringContaining("Reachability was not tested"),
    });
  });

  it("does not accept an incomplete controller configuration", async () => {
    const result = await validateControllerConfiguration({
      type: "lenel",
      name: "Test controller",
      apiEndpoint: "",
      isActive: true,
    });

    expect(result).toEqual({ status: "invalid", message: "API endpoint is required" });
  });

  it("does not perform an outbound request during configuration validation", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await validateControllerConfiguration({
      type: "lenel",
      name: "Test controller",
      apiEndpoint: "https://controller.invalid/api",
      isActive: true,
    });
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
