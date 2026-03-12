/**
 * Microsoft Intune Integration (via Microsoft Graph API)
 *
 * Connects to Microsoft Intune MDM to sync device inventory,
 * compliance policies, and device posture.
 *
 * Docs: https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview
 */

import { logger } from "../routes/shared";

const log = logger.child("intune-integration");

export interface IntuneConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface IntuneDevice {
  id: string;
  deviceName: string;
  managedDeviceOwnerType: string;
  operatingSystem: string;
  osVersion: string;
  model: string;
  manufacturer: string;
  serialNumber: string;
  imei: string;
  wiFiMacAddress: string;
  isEncrypted: boolean;
  isSupervised: boolean;
  jailBroken: string;
  complianceState: "compliant" | "noncompliant" | "conflict" | "unknown";
  managementAgent: string;
  lastSyncDateTime: string;
  enrolledDateTime: string;
  userPrincipalName: string;
  emailAddress: string;
  deviceRegistrationState: string;
  managementState: string;
  exchangeAccessState: string;
  deviceCategoryDisplayName: string;
  freeStorageSpaceInBytes: number;
  totalStorageSpaceInBytes: number;
}

export interface IntuneCompliancePolicy {
  id: string;
  displayName: string;
  description: string;
  platform: string;
  passwordRequired: boolean;
  passwordMinimumLength: number;
  storageRequireEncryption: boolean;
  securityBlockJailbrokenDevices: boolean;
  osMinimumVersion: string;
  osMaximumVersion: string;
}

interface GraphTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

const tokenCache = new Map<string, { token: string; expiresAt: number }>();

async function getAccessToken(config: IntuneConfig): Promise<string> {
  const cacheKey = `${config.tenantId}:${config.clientId}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    return cached.token;
  }

  const url = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    scope: "https://graph.microsoft.com/.default",
  });

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!resp.ok) {
    throw new Error(`Intune OAuth failed: ${resp.status} ${resp.statusText}`);
  }

  const data = (await resp.json()) as GraphTokenResponse;
  tokenCache.set(cacheKey, {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  });
  return data.access_token;
}

/**
 * Fetch all managed devices from Intune
 */
export async function fetchIntuneDevices(config: IntuneConfig): Promise<IntuneDevice[]> {
  const token = await getAccessToken(config);
  const devices: IntuneDevice[] = [];
  let nextLink: string | null = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices";

  while (nextLink) {
    const resp = await fetch(nextLink, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    });

    if (!resp.ok) {
      throw new Error(`Intune device list failed: ${resp.status}`);
    }

    const data = (await resp.json()) as { value: IntuneDevice[]; "@odata.nextLink"?: string };
    devices.push(...data.value);
    nextLink = data["@odata.nextLink"] || null;
  }

  log.info(`Fetched ${devices.length} devices from Microsoft Intune`);
  return devices;
}

/**
 * Fetch device detail by ID
 */
export async function fetchIntuneDeviceDetail(config: IntuneConfig, deviceId: string): Promise<IntuneDevice> {
  const token = await getAccessToken(config);

  const resp = await fetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Intune device detail failed: ${resp.status}`);
  }

  return (await resp.json()) as IntuneDevice;
}

/**
 * Fetch compliance policies from Intune
 */
export async function fetchIntuneCompliancePolicies(config: IntuneConfig): Promise<IntuneCompliancePolicy[]> {
  const token = await getAccessToken(config);

  const resp = await fetch("https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Intune compliance policies failed: ${resp.status}`);
  }

  const data = (await resp.json()) as { value: IntuneCompliancePolicy[] };
  log.info(`Fetched ${data.value.length} compliance policies from Intune`);
  return data.value;
}

/**
 * Send remote lock command via Intune
 */
export async function sendIntuneRemoteLock(config: IntuneConfig, deviceId: string): Promise<void> {
  const token = await getAccessToken(config);

  const resp = await fetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceId}/remoteLock`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Intune remote lock failed: ${resp.status}`);
  }

  log.info(`Remote lock sent to Intune device ${deviceId}`);
}

/**
 * Send remote wipe command via Intune
 */
export async function sendIntuneRemoteWipe(config: IntuneConfig, deviceId: string): Promise<void> {
  const token = await getAccessToken(config);

  const resp = await fetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceId}/wipe`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ keepEnrollmentData: false, keepUserData: false }),
  });

  if (!resp.ok) {
    throw new Error(`Intune remote wipe failed: ${resp.status}`);
  }

  log.warn(`Remote wipe sent to Intune device ${deviceId}`);
}

/**
 * Sync a single device in Intune (request re-check-in)
 */
export async function syncIntuneDevice(config: IntuneConfig, deviceId: string): Promise<void> {
  const token = await getAccessToken(config);

  const resp = await fetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceId}/syncDevice`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`Intune sync failed: ${resp.status}`);
  }

  log.info(`Sync requested for Intune device ${deviceId}`);
}

/**
 * Normalize Intune device data into our internal format
 */
export function normalizeIntuneDevice(device: IntuneDevice): {
  deviceName: string;
  platform: string;
  osVersion: string;
  model: string;
  manufacturer: string;
  serialNumber: string;
  imei: string;
  macAddress: string;
  mdmProvider: string;
  mdmDeviceId: string;
  mdmEnrolledAt: string;
  complianceStatus: string;
  isEncrypted: boolean;
  isRooted: boolean;
  hasMdm: boolean;
  lastCheckIn: string;
} {
  const platformMap: Record<string, string> = {
    iOS: "ios",
    Android: "android",
    Windows: "windows",
    macOS: "macos",
    Linux: "linux",
  };

  const complianceMap: Record<string, string> = {
    compliant: "compliant",
    noncompliant: "non-compliant",
    conflict: "non-compliant",
    unknown: "unknown",
  };

  return {
    deviceName: device.deviceName,
    platform: platformMap[device.operatingSystem] || device.operatingSystem.toLowerCase(),
    osVersion: device.osVersion,
    model: device.model,
    manufacturer: device.manufacturer,
    serialNumber: device.serialNumber,
    imei: device.imei,
    macAddress: device.wiFiMacAddress,
    mdmProvider: "intune",
    mdmDeviceId: device.id,
    mdmEnrolledAt: device.enrolledDateTime,
    complianceStatus: complianceMap[device.complianceState] || "unknown",
    isEncrypted: device.isEncrypted,
    isRooted: device.jailBroken === "True",
    hasMdm: true,
    lastCheckIn: device.lastSyncDateTime,
  };
}

export function invalidateIntuneTokenCache(tenantId?: string): void {
  if (tenantId) {
    const keys = Array.from(tokenCache.keys());
    for (const key of keys) {
      if (key.startsWith(tenantId)) tokenCache.delete(key);
    }
  } else {
    tokenCache.clear();
  }
}
