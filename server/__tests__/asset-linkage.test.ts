import { describe, expect, it } from "vitest";
import { assetReferencesMatch, normalizeAssetReferences } from "../asset-linkage";

describe("asset linkage", () => {
  it("matches exact identifiers rather than substrings", () => {
    expect(assetReferencesMatch(["10.0.1.50"], ["10.0.1.5"])).toBe(false);
    expect(assetReferencesMatch(["web-01-prod"], ["web-01"])).toBe(false);
    expect(assetReferencesMatch(["10.0.1.5"], ["10.0.1.5"])).toBe(true);
  });

  it("matches identifiers case-insensitively across supported object shapes", () => {
    expect(assetReferencesMatch([{ hostname: "WEB-01", ipAddress: "10.0.1.5" }], ["web-01"])).toBe(true);
    expect(assetReferencesMatch([{ asset_id: "ASSET-123" }], ["asset-123"])).toBe(true);
  });

  it("normalizes JSON-encoded arrays without serializing for matching", () => {
    expect(normalizeAssetReferences('[{"fqdn":"Host.Example"}]')).toEqual(["host.example"]);
  });
});
