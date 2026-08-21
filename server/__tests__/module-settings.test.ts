import { describe, expect, it } from "vitest";
import {
  CORE_MODULES,
  MODULE_KEYS,
  canManageModuleSettings,
  getDefaultEnabledModules,
  isSupportedModuleKey,
} from "../module-settings";

describe("module settings policy", () => {
  it("defaults a fresh organization to exactly the five core destinations", () => {
    expect(getDefaultEnabledModules()).toEqual([...CORE_MODULES]);
  });

  it("accepts only server-defined module keys", () => {
    expect(MODULE_KEYS.length).toBeGreaterThan(CORE_MODULES.length);
    expect(isSupportedModuleKey("AI Analyst")).toBe(true);
    expect(isSupportedModuleKey("arbitrary-client-module")).toBe(false);
  });

  it("allows only owner and admin members to manage settings", () => {
    expect(canManageModuleSettings("owner", false)).toBe(true);
    expect(canManageModuleSettings("admin", false)).toBe(true);
    expect(canManageModuleSettings("analyst", false)).toBe(false);
    expect(canManageModuleSettings("read_only", false)).toBe(false);
    expect(canManageModuleSettings("owner", true)).toBe(false);
  });
});
