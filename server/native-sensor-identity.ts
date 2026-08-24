export type SensorSupersessionMatchBasis = "machine_identity" | "hostname_platform_legacy";

export interface SensorIdentityRecord {
  hostname: string;
  platform: string;
  machineIdentity: string | null;
  machineIdentitySource: string | null;
}

export function getSensorSupersessionMatchBasis(
  prior: SensorIdentityRecord,
  current: SensorIdentityRecord,
): SensorSupersessionMatchBasis | null {
  if (
    prior.machineIdentity &&
    current.machineIdentity &&
    prior.machineIdentity === current.machineIdentity &&
    prior.machineIdentitySource === current.machineIdentitySource
  ) {
    return prior.machineIdentitySource === "hostname_fallback" ? "hostname_platform_legacy" : "machine_identity";
  }

  if (
    !prior.machineIdentity &&
    !prior.machineIdentitySource &&
    prior.hostname === current.hostname &&
    prior.platform === current.platform
  ) {
    return "hostname_platform_legacy";
  }

  return null;
}
