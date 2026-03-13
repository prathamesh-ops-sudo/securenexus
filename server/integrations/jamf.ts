/**
 * Jamf Pro API Integration
 *
 * Connects to Jamf Pro MDM to sync mobile device inventory,
 * compliance status, and installed applications.
 *
 * Docs: https://developer.jamf.com/jamf-pro/reference
 */

import { logger } from "../routes/shared";

const log = logger.child("jamf-integration");

export interface JamfConfig {
  baseUrl: string; // e.g. https://yourcompany.jamfcloud.com
  clientId: string;
  clientSecret: string;
}

export interface JamfDevice {
  id: number;
  name: string;
  serialNumber: string;
  udid: string;
  model: string;
  modelIdentifier: string;
  osVersion: string;
  osBuild: string;
  platform: "ios" | "macos" | "tvos";
  managed: boolean;
  supervised: boolean;
  lastInventoryUpdate: string;
  ipAddress: string;
  macAddress: string;
  isEncrypted: boolean;
  isPasscodeLockEnabled: boolean;
  isRooted: boolean;
  installedApps: JamfApp[];
}

export interface JamfApp {
  name: string;
  bundleId: string;
  version: string;
  isManaged: boolean;
  isSideloaded: boolean;
}

interface JamfTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

const tokenCache = new Map<string, { token: string; expiresAt: number }>();

async function getAccessToken(config: JamfConfig): Promise<string> {
  const cacheKey = `${config.baseUrl}:${config.clientId}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    return cached.token;
  }

  const url = `${config.baseUrl}/api/oauth/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!resp.ok) {
    throw new Error(`Jamf OAuth failed: ${resp.status} ${resp.statusText}`);
  }

  const data = (await resp.json()) as JamfTokenResponse;
  tokenCache.set(cacheKey, {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  });
  return data.access_token;
}

/**
 * Fetch all mobile devices from Jamf Pro
 */
export async function fetchJamfDevices(config: JamfConfig): Promise<JamfDevice[]> {
  const token = await getAccessToken(config);

  const resp = await fetch(`${config.baseUrl}/api/v2/mobile-devices`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Jamf device list failed: ${resp.status}`);
  }

  const data = (await resp.json()) as { results: JamfDevice[] };
  log.info(`Fetched ${data.results.length} devices from Jamf Pro`);
  return data.results;
}

/**
 * Fetch detailed device info including installed apps
 */
export async function fetchJamfDeviceDetail(config: JamfConfig, deviceId: number): Promise<JamfDevice> {
  const token = await getAccessToken(config);

  const resp = await fetch(`${config.baseUrl}/api/v2/mobile-devices/${deviceId}/detail`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Jamf device detail failed: ${resp.status}`);
  }

  return (await resp.json()) as JamfDevice;
}

/**
 * Fetch computer (macOS) devices from Jamf Pro
 */
export async function fetchJamfComputers(config: JamfConfig): Promise<JamfDevice[]> {
  const token = await getAccessToken(config);

  const resp = await fetch(`${config.baseUrl}/api/v1/computers-inventory`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Jamf computers list failed: ${resp.status}`);
  }

  const data = (await resp.json()) as { results: JamfDevice[] };
  log.info(`Fetched ${data.results.length} computers from Jamf Pro`);
  return data.results;
}

/**
 * Send remote lock command to a device
 */
export async function sendJamfRemoteLock(config: JamfConfig, deviceId: number): Promise<void> {
  const token = await getAccessToken(config);

  const resp = await fetch(`${config.baseUrl}/api/v2/mobile-devices/${deviceId}/commands`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ commandType: "DEVICE_LOCK" }),
  });

  if (!resp.ok) {
    throw new Error(`Jamf remote lock failed: ${resp.status}`);
  }

  log.info(`Remote lock sent to Jamf device ${deviceId}`);
}

/**
 * Send remote wipe command to a device
 */
export async function sendJamfRemoteWipe(config: JamfConfig, deviceId: number): Promise<void> {
  const token = await getAccessToken(config);

  const resp = await fetch(`${config.baseUrl}/api/v2/mobile-devices/${deviceId}/commands`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ commandType: "ERASE_DEVICE" }),
  });

  if (!resp.ok) {
    throw new Error(`Jamf remote wipe failed: ${resp.status}`);
  }

  log.warn(`Remote wipe sent to Jamf device ${deviceId}`);
}

/**
 * Normalize Jamf device data into our internal format
 */
export function normalizeJamfDevice(device: JamfDevice): {
  deviceName: string;
  platform: string;
  osVersion: string;
  model: string;
  serialNumber: string;
  macAddress: string;
  mdmProvider: string;
  mdmDeviceId: string;
  isEncrypted: boolean;
  isRooted: boolean;
  hasScreenLock: boolean;
  hasMdm: boolean;
  lastKnownIp: string;
  installedApps: JamfApp[];
  sideloadedApps: JamfApp[];
} {
  const sideloaded = (device.installedApps || []).filter((a) => a.isSideloaded);

  return {
    deviceName: device.name,
    platform: device.platform === "ios" ? "ios" : "macos",
    osVersion: device.osVersion,
    model: device.model,
    serialNumber: device.serialNumber,
    macAddress: device.macAddress,
    mdmProvider: "jamf",
    mdmDeviceId: String(device.id),
    isEncrypted: device.isEncrypted,
    isRooted: device.isRooted || false,
    hasScreenLock: device.isPasscodeLockEnabled,
    hasMdm: device.managed,
    lastKnownIp: device.ipAddress,
    installedApps: device.installedApps || [],
    sideloadedApps: sideloaded,
  };
}

export function invalidateJamfTokenCache(baseUrl?: string): void {
  if (baseUrl) {
    const keys = Array.from(tokenCache.keys());
    for (const key of keys) {
      if (key.startsWith(baseUrl)) tokenCache.delete(key);
    }
  } else {
    tokenCache.clear();
  }
}
