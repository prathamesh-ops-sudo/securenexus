import { describe, expect, it } from "vitest";
import { getSensorSupersessionMatchBasis, getSensorSupersessionMatches } from "../native-sensor-identity";

const current = {
  hostname: "demo-host",
  platform: "linux",
  machineIdentity: "machine-a",
  machineIdentitySource: "machine_id",
};

describe("native sensor supersession identity", () => {
  it("prefers an exact machine identity match", () => {
    expect(getSensorSupersessionMatchBasis(current, current)).toBe("machine_identity");
  });

  it("uses hostname and platform only for a legacy identity-less row", () => {
    expect(
      getSensorSupersessionMatchBasis({ ...current, machineIdentity: null, machineIdentitySource: null }, current),
    ).toBe("hostname_platform_legacy");
  });

  it("does not merge rows with different machine identities", () => {
    expect(getSensorSupersessionMatchBasis({ ...current, machineIdentity: "machine-b" }, current)).toBeNull();
  });

  it("does not use hostname fallback across platforms", () => {
    expect(
      getSensorSupersessionMatchBasis(
        { ...current, machineIdentity: null, machineIdentitySource: null },
        { ...current, platform: "windows" },
      ),
    ).toBeNull();
  });

  it("does not use hostname fallback when the legacy source is inconsistent", () => {
    expect(
      getSensorSupersessionMatchBasis(
        { ...current, machineIdentity: null, machineIdentitySource: "hostname_fallback" },
        current,
      ),
    ).toBeNull();
  });

  it("does not describe an explicit hostname fallback as machine identity evidence", () => {
    const fallback = {
      ...current,
      machineIdentity: "demo-host",
      machineIdentitySource: "hostname_fallback",
    };
    expect(getSensorSupersessionMatchBasis(fallback, fallback)).toBe("hostname_platform_legacy");
  });

  it("returns every matching stale row with its own basis", () => {
    const matches = getSensorSupersessionMatches(
      [
        { id: "machine-row", ...current },
        { id: "legacy-row", ...current, machineIdentity: null, machineIdentitySource: null },
        { id: "different-machine-row", ...current, machineIdentity: "machine-b" },
      ],
      current,
    );

    expect(matches).toEqual([
      { candidate: { id: "machine-row", ...current }, basis: "machine_identity" },
      {
        candidate: { id: "legacy-row", ...current, machineIdentity: null, machineIdentitySource: null },
        basis: "hostname_platform_legacy",
      },
    ]);
  });
});
