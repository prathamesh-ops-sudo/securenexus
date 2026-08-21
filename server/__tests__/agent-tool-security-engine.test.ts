import { describe, expect, it } from "vitest";
import { getToolCatalog } from "../agent-tool-security-engine";

describe("agent tool catalog", () => {
  it("initializes the static catalog without throwing", () => {
    const catalog = getToolCatalog();

    expect(catalog.length).toBeGreaterThan(0);
    expect(catalog[0]).toMatchObject({
      verified: true,
      enabled: true,
    });
  });
});
