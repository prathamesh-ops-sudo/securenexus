import type { Express } from "express";
import { eq, and, desc, sql, count, gte, lte, isNull } from "drizzle-orm";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext, requireOrgId } from "../rbac";
import { db } from "../db";
import { createAlertAndPublish } from "../alert-events";
import {
  mobileDevices,
  devicePostureChecks,
  mobileThreats,
  ztnaPolicies,
  remoteWorkerSessions,
  MOBILE_PLATFORMS,
  DEVICE_COMPLIANCE_STATUSES,
  MDM_PROVIDERS,
  ZTNA_ACTIONS,
  DEVICE_RISK_LEVELS,
  MOBILE_THREAT_TYPES,
} from "@shared/schema";

const log = logger.child("mobile-security");

const ALLOWED_PLATFORMS = MOBILE_PLATFORMS as readonly string[];
const ALLOWED_COMPLIANCE = DEVICE_COMPLIANCE_STATUSES as readonly string[];
const ALLOWED_MDM = MDM_PROVIDERS as readonly string[];
const ALLOWED_ZTNA_ACTIONS = ZTNA_ACTIONS as readonly string[];
const ALLOWED_RISK_LEVELS = DEVICE_RISK_LEVELS as readonly string[];
const ALLOWED_THREAT_TYPES = MOBILE_THREAT_TYPES as readonly string[];

/** Compute a risk score based on device posture signals */
function computeDeviceRiskScore(device: {
  isRooted?: boolean | null;
  isJailbroken?: boolean | null;
  isEncrypted?: boolean | null;
  hasScreenLock?: boolean | null;
  hasMdm?: boolean | null;
  isVpnActive?: boolean | null;
  hasFirewall?: boolean | null;
  osVersion?: string | null;
  sideloadedApps?: unknown;
}): { score: number; level: string; factors: string[] } {
  let score = 0;
  const factors: string[] = [];

  if (device.isRooted || device.isJailbroken) {
    score += 40;
    factors.push("Device is rooted/jailbroken");
  }
  if (!device.isEncrypted) {
    score += 15;
    factors.push("Storage not encrypted");
  }
  if (!device.hasScreenLock) {
    score += 10;
    factors.push("No screen lock configured");
  }
  if (!device.hasMdm) {
    score += 15;
    factors.push("Not enrolled in MDM");
  }
  if (!device.isVpnActive) {
    score += 5;
    factors.push("VPN not active");
  }
  if (!device.hasFirewall) {
    score += 5;
    factors.push("Firewall disabled");
  }

  const sideloaded = device.sideloadedApps;
  if (Array.isArray(sideloaded) && sideloaded.length > 0) {
    score += 10;
    factors.push(`${sideloaded.length} sideloaded app(s) detected`);
  }

  score = Math.min(score, 100);
  const level = score >= 80 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";

  return { score, level, factors };
}

/** Compute remote worker session risk score */
function computeSessionRiskScore(session: {
  vpnConnected?: boolean | null;
  isOffHours?: boolean | null;
  isNewLocation?: boolean | null;
  country?: string | null;
}): { score: number; factors: string[] } {
  let score = 0;
  const factors: string[] = [];

  if (!session.vpnConnected) {
    score += 25;
    factors.push("Not connected via VPN");
  }
  if (session.isOffHours) {
    score += 20;
    factors.push("Access during off-hours");
  }
  if (session.isNewLocation) {
    score += 30;
    factors.push("New/unusual location");
  }

  score = Math.min(score, 100);
  return { score, factors };
}

export function registerMobileSecurityRoutes(app: Express): void {
  // =========================================================================
  // MOBILE DEVICES
  // =========================================================================

  /** List all mobile devices for the org */
  app.get("/api/mobile/devices", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const platform = req.query.platform as string | undefined;
      const compliance = req.query.compliance as string | undefined;
      const risk = req.query.risk as string | undefined;

      const conditions = [eq(mobileDevices.orgId, orgId)];
      if (platform && ALLOWED_PLATFORMS.includes(platform)) {
        conditions.push(eq(mobileDevices.platform, platform));
      }
      if (compliance && ALLOWED_COMPLIANCE.includes(compliance)) {
        conditions.push(eq(mobileDevices.complianceStatus, compliance));
      }
      if (risk && ALLOWED_RISK_LEVELS.includes(risk)) {
        conditions.push(eq(mobileDevices.riskLevel, risk));
      }

      const devices = await db
        .select()
        .from(mobileDevices)
        .where(and(...conditions))
        .orderBy(desc(mobileDevices.updatedAt))
        .limit(500);
      res.json(devices);
    } catch (err) {
      log.error("Failed to list mobile devices", { error: String(err) });
      res.status(500).json({ message: "Failed to list mobile devices" });
    }
  });

  /** Get a single mobile device */
  app.get("/api/mobile/devices/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [device] = await db
        .select()
        .from(mobileDevices)
        .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)));
      if (!device) return res.status(404).json({ message: "Device not found" });
      res.json(device);
    } catch (err) {
      log.error("Failed to get mobile device", { error: String(err) });
      res.status(500).json({ message: "Failed to get mobile device" });
    }
  });

  /** Register a new mobile device */
  app.post(
    "/api/mobile/devices",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          deviceName,
          platform,
          osVersion,
          model,
          manufacturer,
          serialNumber,
          imei,
          macAddress,
          mdmProvider,
          mdmDeviceId,
          userId,
          isEncrypted,
          isRooted,
          isJailbroken,
          hasScreenLock,
          hasFirewall,
          isVpnActive,
          vpnProvider,
          lastKnownIp,
          lastKnownLocation,
          lastKnownCountry,
          installedApps,
          sideloadedApps,
          certificates,
          tags,
          metadata,
        } = req.body;

        if (!deviceName || typeof deviceName !== "string" || deviceName.trim().length === 0) {
          return res.status(400).json({ message: "Device name is required" });
        }
        if (!platform || !ALLOWED_PLATFORMS.includes(platform)) {
          return res.status(400).json({ message: `Invalid platform. Allowed: ${ALLOWED_PLATFORMS.join(", ")}` });
        }
        if (mdmProvider && !ALLOWED_MDM.includes(mdmProvider)) {
          return res.status(400).json({ message: `Invalid MDM provider. Allowed: ${ALLOWED_MDM.join(", ")}` });
        }

        const riskData = computeDeviceRiskScore({
          isRooted,
          isJailbroken,
          isEncrypted,
          hasScreenLock,
          hasMdm: !!mdmProvider,
          isVpnActive,
          hasFirewall,
          sideloadedApps,
        });

        const [device] = await db
          .insert(mobileDevices)
          .values({
            orgId,
            userId: userId || null,
            deviceName: deviceName.trim(),
            platform,
            osVersion: osVersion || null,
            model: model || null,
            manufacturer: manufacturer || null,
            serialNumber: serialNumber || null,
            imei: imei || null,
            macAddress: macAddress || null,
            mdmProvider: mdmProvider || null,
            mdmDeviceId: mdmDeviceId || null,
            mdmEnrolledAt: mdmProvider ? new Date() : null,
            lastCheckIn: new Date(),
            complianceStatus: mdmProvider ? "pending" : "unknown",
            riskLevel: riskData.level,
            riskScore: riskData.score,
            isEncrypted: isEncrypted === true,
            isRooted: isRooted === true,
            isJailbroken: isJailbroken === true,
            hasMdm: !!mdmProvider,
            hasScreenLock: hasScreenLock === true,
            hasFirewall: hasFirewall === true,
            isVpnActive: isVpnActive === true,
            vpnProvider: vpnProvider || null,
            lastKnownIp: lastKnownIp || null,
            lastKnownLocation: lastKnownLocation || null,
            lastKnownCountry: lastKnownCountry || null,
            installedApps: installedApps || null,
            sideloadedApps: sideloadedApps || null,
            certificates: certificates || null,
            tags: tags || null,
            metadata: metadata || null,
            status: "active",
          })
          .returning();

        log.info(`Mobile device registered: ${device.deviceName} (${device.platform}) in org ${orgId}`);
        res.status(201).json(device);
      } catch (err) {
        log.error("Failed to register mobile device", { error: String(err) });
        res.status(500).json({ message: "Failed to register mobile device" });
      }
    },
  );

  /** Update a mobile device */
  app.patch(
    "/api/mobile/devices/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(mobileDevices)
          .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)));
        if (!existing) return res.status(404).json({ message: "Device not found" });

        const allowedFields = [
          "deviceName",
          "platform",
          "osVersion",
          "model",
          "manufacturer",
          "serialNumber",
          "imei",
          "macAddress",
          "mdmProvider",
          "mdmDeviceId",
          "userId",
          "complianceStatus",
          "isEncrypted",
          "isRooted",
          "isJailbroken",
          "hasScreenLock",
          "hasFirewall",
          "isVpnActive",
          "vpnProvider",
          "lastKnownIp",
          "lastKnownLocation",
          "lastKnownCountry",
          "installedApps",
          "sideloadedApps",
          "certificates",
          "tags",
          "metadata",
          "status",
        ];
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }

        if (updates.platform && !ALLOWED_PLATFORMS.includes(updates.platform as string)) {
          return res.status(400).json({ message: "Invalid platform" });
        }
        if (updates.complianceStatus && !ALLOWED_COMPLIANCE.includes(updates.complianceStatus as string)) {
          return res.status(400).json({ message: "Invalid compliance status" });
        }

        // Recompute risk score on posture changes
        const merged = { ...existing, ...updates };
        const riskData = computeDeviceRiskScore({
          isRooted: merged.isRooted as boolean,
          isJailbroken: merged.isJailbroken as boolean,
          isEncrypted: merged.isEncrypted as boolean,
          hasScreenLock: merged.hasScreenLock as boolean,
          hasMdm: merged.hasMdm as boolean,
          isVpnActive: merged.isVpnActive as boolean,
          hasFirewall: merged.hasFirewall as boolean,
          sideloadedApps: merged.sideloadedApps,
        });
        updates.riskScore = riskData.score;
        updates.riskLevel = riskData.level;

        const [updated] = await db
          .update(mobileDevices)
          .set(updates as Record<string, unknown> as typeof mobileDevices.$inferInsert)
          .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)))
          .returning();
        res.json(updated);
      } catch (err) {
        log.error("Failed to update mobile device", { error: String(err) });
        res.status(500).json({ message: "Failed to update mobile device" });
      }
    },
  );

  /** Delete a mobile device */
  app.delete("/api/mobile/devices/:id", isAuthenticated, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(mobileDevices)
        .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "Device not found" });

      await db
        .delete(mobileDevices)
        .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)));
      res.json({ message: "Device deleted" });
    } catch (err) {
      log.error("Failed to delete mobile device", { error: String(err) });
      res.status(500).json({ message: "Failed to delete mobile device" });
    }
  });

  /** Bulk sync devices from MDM provider */
  app.post("/api/mobile/devices/sync", isAuthenticated, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { provider, devices: deviceList } = req.body;

      if (!provider || !ALLOWED_MDM.includes(provider)) {
        return res.status(400).json({ message: `Invalid MDM provider. Allowed: ${ALLOWED_MDM.join(", ")}` });
      }
      if (!Array.isArray(deviceList) || deviceList.length === 0) {
        return res.status(400).json({ message: "devices array is required" });
      }
      if (deviceList.length > 1000) {
        return res.status(400).json({ message: "Maximum 1000 devices per sync" });
      }

      let synced = 0;
      let created = 0;
      let updated = 0;

      for (const d of deviceList) {
        if (!d.deviceName || !d.platform) continue;

        // Check if device already exists by mdmDeviceId
        if (d.mdmDeviceId) {
          const [existing] = await db
            .select()
            .from(mobileDevices)
            .where(and(eq(mobileDevices.orgId, orgId), eq(mobileDevices.mdmDeviceId, d.mdmDeviceId)));

          if (existing) {
            const riskData = computeDeviceRiskScore({
              isRooted: d.isRooted ?? existing.isRooted,
              isJailbroken: d.isJailbroken ?? existing.isJailbroken,
              isEncrypted: d.isEncrypted ?? existing.isEncrypted,
              hasScreenLock: d.hasScreenLock ?? existing.hasScreenLock,
              hasMdm: true,
              isVpnActive: d.isVpnActive ?? existing.isVpnActive,
              hasFirewall: d.hasFirewall ?? existing.hasFirewall,
              sideloadedApps: d.sideloadedApps ?? existing.sideloadedApps,
            });

            await db
              .update(mobileDevices)
              .set({
                deviceName: d.deviceName || existing.deviceName,
                platform: d.platform || existing.platform,
                osVersion: d.osVersion ?? existing.osVersion,
                model: d.model ?? existing.model,
                manufacturer: d.manufacturer ?? existing.manufacturer,
                isEncrypted: d.isEncrypted ?? existing.isEncrypted,
                isRooted: d.isRooted ?? existing.isRooted,
                isJailbroken: d.isJailbroken ?? existing.isJailbroken,
                hasScreenLock: d.hasScreenLock ?? existing.hasScreenLock,
                complianceStatus: d.complianceStatus || existing.complianceStatus,
                riskScore: riskData.score,
                riskLevel: riskData.level,
                lastCheckIn: new Date(),
                updatedAt: new Date(),
                installedApps: d.installedApps ?? existing.installedApps,
                sideloadedApps: d.sideloadedApps ?? existing.sideloadedApps,
              } as typeof mobileDevices.$inferInsert)
              .where(eq(mobileDevices.id, existing.id));
            updated++;
            synced++;
            continue;
          }
        }

        // Create new device
        const riskData = computeDeviceRiskScore({
          isRooted: d.isRooted,
          isJailbroken: d.isJailbroken,
          isEncrypted: d.isEncrypted,
          hasScreenLock: d.hasScreenLock,
          hasMdm: true,
          isVpnActive: d.isVpnActive,
          hasFirewall: d.hasFirewall,
          sideloadedApps: d.sideloadedApps,
        });

        await db.insert(mobileDevices).values({
          orgId,
          deviceName: d.deviceName,
          platform: d.platform,
          osVersion: d.osVersion || null,
          model: d.model || null,
          manufacturer: d.manufacturer || null,
          serialNumber: d.serialNumber || null,
          imei: d.imei || null,
          macAddress: d.macAddress || null,
          mdmProvider: provider,
          mdmDeviceId: d.mdmDeviceId || null,
          mdmEnrolledAt: new Date(),
          lastCheckIn: new Date(),
          complianceStatus: d.complianceStatus || "pending",
          riskLevel: riskData.level,
          riskScore: riskData.score,
          isEncrypted: d.isEncrypted === true,
          isRooted: d.isRooted === true,
          isJailbroken: d.isJailbroken === true,
          hasMdm: true,
          hasScreenLock: d.hasScreenLock === true,
          hasFirewall: d.hasFirewall === true,
          isVpnActive: d.isVpnActive === true,
          installedApps: d.installedApps || null,
          sideloadedApps: d.sideloadedApps || null,
          status: "active",
        });
        created++;
        synced++;
      }

      log.info(`MDM sync complete: ${synced} synced (${created} new, ${updated} updated) from ${provider}`);
      res.json({ synced, created, updated, provider });
    } catch (err) {
      log.error("Failed to sync MDM devices", { error: String(err) });
      res.status(500).json({ message: "Failed to sync devices" });
    }
  });

  // =========================================================================
  // DEVICE POSTURE CHECKS
  // =========================================================================

  /** Run posture check on a device */
  app.post(
    "/api/mobile/devices/:id/posture-check",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [device] = await db
          .select()
          .from(mobileDevices)
          .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)));
        if (!device) return res.status(404).json({ message: "Device not found" });

        // Run posture checks based on device state
        const checks: Array<{
          checkType: string;
          checkName: string;
          passed: boolean;
          details: string;
          severity: string;
          remediationHint: string;
        }> = [];

        checks.push({
          checkType: "encryption",
          checkName: "Storage Encryption",
          passed: device.isEncrypted === true,
          details: device.isEncrypted ? "Device storage is encrypted" : "Device storage is NOT encrypted",
          severity: "high",
          remediationHint: "Enable full-disk encryption in device settings",
        });

        checks.push({
          checkType: "root_jailbreak",
          checkName: "Root/Jailbreak Detection",
          passed: !device.isRooted && !device.isJailbroken,
          details:
            device.isRooted || device.isJailbroken ? "Device is rooted or jailbroken" : "No root/jailbreak detected",
          severity: "critical",
          remediationHint: "Remove root/jailbreak and restore device to factory settings",
        });

        checks.push({
          checkType: "screen_lock",
          checkName: "Screen Lock",
          passed: device.hasScreenLock === true,
          details: device.hasScreenLock ? "Screen lock is enabled" : "No screen lock configured",
          severity: "medium",
          remediationHint: "Enable PIN, pattern, or biometric screen lock",
        });

        checks.push({
          checkType: "mdm_enrollment",
          checkName: "MDM Enrollment",
          passed: device.hasMdm === true,
          details: device.hasMdm ? `Enrolled in ${device.mdmProvider || "MDM"}` : "Not enrolled in any MDM solution",
          severity: "high",
          remediationHint: "Enroll device in corporate MDM (Jamf, Intune, or Workspace ONE)",
        });

        checks.push({
          checkType: "vpn",
          checkName: "VPN Connection",
          passed: device.isVpnActive === true,
          details: device.isVpnActive
            ? `VPN active via ${device.vpnProvider || "unknown provider"}`
            : "VPN not connected",
          severity: "medium",
          remediationHint: "Connect to corporate VPN before accessing resources",
        });

        checks.push({
          checkType: "firewall",
          checkName: "Firewall Status",
          passed: device.hasFirewall === true,
          details: device.hasFirewall ? "Firewall is enabled" : "Firewall is disabled",
          severity: "medium",
          remediationHint: "Enable the device firewall in system settings",
        });

        const sideloaded = device.sideloadedApps as unknown[];
        checks.push({
          checkType: "sideloaded_apps",
          checkName: "Sideloaded App Detection",
          passed: !Array.isArray(sideloaded) || sideloaded.length === 0,
          details:
            Array.isArray(sideloaded) && sideloaded.length > 0
              ? `${sideloaded.length} sideloaded app(s) detected`
              : "No sideloaded apps detected",
          severity: "high",
          remediationHint: "Remove sideloaded applications and only install from official app stores",
        });

        // Store all checks
        const insertedChecks = [];
        for (const check of checks) {
          const [inserted] = await db
            .insert(devicePostureChecks)
            .values({
              orgId,
              deviceId: device.id,
              checkType: check.checkType,
              checkName: check.checkName,
              passed: check.passed,
              details: check.details,
              severity: check.severity,
              remediationHint: check.remediationHint,
            })
            .returning();
          insertedChecks.push(inserted);
        }

        // Update device compliance based on check results
        const allPassed = checks.every((c) => c.passed);
        const hasCriticalFailure = checks.some((c) => !c.passed && c.severity === "critical");
        const newCompliance = allPassed ? "compliant" : hasCriticalFailure ? "non-compliant" : "pending";

        await db
          .update(mobileDevices)
          .set({
            complianceStatus: newCompliance,
            lastCheckIn: new Date(),
            updatedAt: new Date(),
          } as typeof mobileDevices.$inferInsert)
          .where(eq(mobileDevices.id, device.id));

        res.json({
          deviceId: device.id,
          complianceStatus: newCompliance,
          checksRun: checks.length,
          checksPassed: checks.filter((c) => c.passed).length,
          checksFailed: checks.filter((c) => !c.passed).length,
          checks: insertedChecks,
        });
      } catch (err) {
        log.error("Failed to run posture check", { error: String(err) });
        res.status(500).json({ message: "Failed to run posture check" });
      }
    },
  );

  /** Get posture check history for a device */
  app.get("/api/mobile/devices/:id/posture-checks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [device] = await db
        .select()
        .from(mobileDevices)
        .where(and(eq(mobileDevices.id, String(req.params.id)), eq(mobileDevices.orgId, orgId)));
      if (!device) return res.status(404).json({ message: "Device not found" });

      const checks = await db
        .select()
        .from(devicePostureChecks)
        .where(and(eq(devicePostureChecks.orgId, orgId), eq(devicePostureChecks.deviceId, device.id)))
        .orderBy(desc(devicePostureChecks.checkedAt))
        .limit(200);
      res.json(checks);
    } catch (err) {
      log.error("Failed to get posture checks", { error: String(err) });
      res.status(500).json({ message: "Failed to get posture checks" });
    }
  });

  // =========================================================================
  // MOBILE THREAT DEFENSE (MTD)
  // =========================================================================

  /** List mobile threats */
  app.get("/api/mobile/threats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const severity = req.query.severity as string | undefined;
      const threatType = req.query.threatType as string | undefined;

      const conditions = [eq(mobileThreats.orgId, orgId)];
      if (status) conditions.push(eq(mobileThreats.status, status));
      if (severity) conditions.push(eq(mobileThreats.severity, severity));
      if (threatType && ALLOWED_THREAT_TYPES.includes(threatType)) {
        conditions.push(eq(mobileThreats.threatType, threatType));
      }

      const threats = await db
        .select()
        .from(mobileThreats)
        .where(and(...conditions))
        .orderBy(desc(mobileThreats.detectedAt))
        .limit(500);
      res.json(threats);
    } catch (err) {
      log.error("Failed to list mobile threats", { error: String(err) });
      res.status(500).json({ message: "Failed to list mobile threats" });
    }
  });

  /** Report a mobile threat */
  app.post(
    "/api/mobile/threats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          deviceId,
          threatType,
          severity,
          title,
          description,
          appName,
          appPackage,
          networkSsid,
          sourceIp,
          mitreTactic,
          mitreTechnique,
          metadata,
        } = req.body;

        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "Title is required" });
        }
        if (!threatType || !ALLOWED_THREAT_TYPES.includes(threatType)) {
          return res.status(400).json({ message: `Invalid threat type. Allowed: ${ALLOWED_THREAT_TYPES.join(", ")}` });
        }
        if (!deviceId) {
          return res.status(400).json({ message: "deviceId is required" });
        }

        // Verify device belongs to org
        const [device] = await db
          .select()
          .from(mobileDevices)
          .where(and(eq(mobileDevices.id, deviceId), eq(mobileDevices.orgId, orgId)));
        if (!device) return res.status(400).json({ message: "Device not found in org" });

        const effectiveSeverity = severity && ALLOWED_RISK_LEVELS.includes(severity) ? severity : "medium";

        const [threat] = await db
          .insert(mobileThreats)
          .values({
            orgId,
            deviceId,
            threatType,
            severity: effectiveSeverity,
            title,
            description: description || null,
            appName: appName || null,
            appPackage: appPackage || null,
            networkSsid: networkSsid || null,
            sourceIp: sourceIp || null,
            mitreTactic: mitreTactic || null,
            mitreTechnique: mitreTechnique || null,
            status: "new",
            metadata: (metadata || null) as Record<string, unknown> | null,
          })
          .returning();

        // Auto-create alert for critical/high threats
        if (effectiveSeverity === "critical" || effectiveSeverity === "high") {
          const alert = await createAlertAndPublish({
            orgId,
            source: "mobile_mtd",
            category: "intrusion",
            severity: effectiveSeverity,
            title: `[Mobile] ${title}`,
            description: description || `Mobile threat detected: ${threatType} on device ${device.deviceName}`,
            sourceIp: sourceIp || null,
            status: "new",
            mitreTactic: mitreTactic || null,
            mitreTechnique: mitreTechnique || null,
            rawData: { mobileThreatId: threat.id, threatType, deviceId } as Record<string, unknown>,
            detectedAt: new Date(),
          });

          await db.update(mobileThreats).set({ alertId: alert.id }).where(eq(mobileThreats.id, threat.id));
        }

        res.status(201).json(threat);
      } catch (err) {
        log.error("Failed to create mobile threat", { error: String(err) });
        res.status(500).json({ message: "Failed to create mobile threat" });
      }
    },
  );

  /** Update threat status */
  app.patch(
    "/api/mobile/threats/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(mobileThreats)
          .where(and(eq(mobileThreats.id, String(req.params.id)), eq(mobileThreats.orgId, orgId)));
        if (!existing) return res.status(404).json({ message: "Threat not found" });

        const allowedFields = ["status", "resolvedBy", "metadata"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }

        if (updates.status === "resolved") {
          const user = req.user as Record<string, unknown> | undefined;
          updates.resolvedAt = new Date();
          updates.resolvedBy = user?.id || null;
        }

        const [updated] = await db
          .update(mobileThreats)
          .set(updates as Record<string, unknown> as typeof mobileThreats.$inferInsert)
          .where(and(eq(mobileThreats.id, String(req.params.id)), eq(mobileThreats.orgId, orgId)))
          .returning();
        res.json(updated);
      } catch (err) {
        log.error("Failed to update mobile threat", { error: String(err) });
        res.status(500).json({ message: "Failed to update mobile threat" });
      }
    },
  );

  // =========================================================================
  // ZTNA POLICIES
  // =========================================================================

  /** List ZTNA policies */
  app.get("/api/mobile/ztna/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policies = await db
        .select()
        .from(ztnaPolicies)
        .where(eq(ztnaPolicies.orgId, orgId))
        .orderBy(ztnaPolicies.priority);
      res.json(policies);
    } catch (err) {
      log.error("Failed to list ZTNA policies", { error: String(err) });
      res.status(500).json({ message: "Failed to list ZTNA policies" });
    }
  });

  /** Create a ZTNA policy */
  app.post("/api/mobile/ztna/policies", isAuthenticated, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const user = req.user as Record<string, unknown> | undefined;
      const {
        name,
        description,
        enabled,
        priority,
        conditions,
        action,
        requireMfa,
        allowedPlatforms,
        minOsVersion,
        requireEncryption,
        requireMdm,
        requireScreenLock,
        blockRooted,
        maxRiskScore,
        allowedCountries,
        blockedCountries,
        timeRestrictions,
      } = req.body;

      if (!name || typeof name !== "string" || name.trim().length === 0) {
        return res.status(400).json({ message: "Policy name is required" });
      }
      if (!conditions || typeof conditions !== "object") {
        return res.status(400).json({ message: "Policy conditions are required (JSON object)" });
      }
      if (action && !ALLOWED_ZTNA_ACTIONS.includes(action)) {
        return res.status(400).json({ message: `Invalid action. Allowed: ${ALLOWED_ZTNA_ACTIONS.join(", ")}` });
      }

      const [policy] = await db
        .insert(ztnaPolicies)
        .values({
          orgId,
          name: name.trim(),
          description: description || null,
          enabled: enabled !== false,
          priority: typeof priority === "number" ? priority : 100,
          conditions: conditions as Record<string, unknown>,
          action: action || "deny",
          requireMfa: requireMfa === true,
          allowedPlatforms: allowedPlatforms || null,
          minOsVersion: minOsVersion || null,
          requireEncryption: requireEncryption === true,
          requireMdm: requireMdm === true,
          requireScreenLock: requireScreenLock === true,
          blockRooted: blockRooted !== false,
          maxRiskScore: typeof maxRiskScore === "number" ? maxRiskScore : 70,
          allowedCountries: allowedCountries || null,
          blockedCountries: blockedCountries || null,
          timeRestrictions: timeRestrictions || null,
          createdBy: (user?.id as string) || null,
        })
        .returning();

      log.info(`ZTNA policy created: ${policy.name} (${policy.action}) in org ${orgId}`);
      res.status(201).json(policy);
    } catch (err) {
      log.error("Failed to create ZTNA policy", { error: String(err) });
      res.status(500).json({ message: "Failed to create ZTNA policy" });
    }
  });

  /** Update a ZTNA policy */
  app.put("/api/mobile/ztna/policies/:id", isAuthenticated, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(ztnaPolicies)
        .where(and(eq(ztnaPolicies.id, String(req.params.id)), eq(ztnaPolicies.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "Policy not found" });

      const allowedFields = [
        "name",
        "description",
        "enabled",
        "priority",
        "conditions",
        "action",
        "requireMfa",
        "allowedPlatforms",
        "minOsVersion",
        "requireEncryption",
        "requireMdm",
        "requireScreenLock",
        "blockRooted",
        "maxRiskScore",
        "allowedCountries",
        "blockedCountries",
        "timeRestrictions",
      ];
      const updates: Record<string, unknown> = { updatedAt: new Date() };
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (updates.action && !ALLOWED_ZTNA_ACTIONS.includes(updates.action as string)) {
        return res.status(400).json({ message: "Invalid action" });
      }

      const [updated] = await db
        .update(ztnaPolicies)
        .set(updates as Record<string, unknown> as typeof ztnaPolicies.$inferInsert)
        .where(and(eq(ztnaPolicies.id, String(req.params.id)), eq(ztnaPolicies.orgId, orgId)))
        .returning();
      res.json(updated);
    } catch (err) {
      log.error("Failed to update ZTNA policy", { error: String(err) });
      res.status(500).json({ message: "Failed to update ZTNA policy" });
    }
  });

  /** Delete a ZTNA policy */
  app.delete("/api/mobile/ztna/policies/:id", isAuthenticated, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(ztnaPolicies)
        .where(and(eq(ztnaPolicies.id, String(req.params.id)), eq(ztnaPolicies.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "Policy not found" });

      await db
        .delete(ztnaPolicies)
        .where(and(eq(ztnaPolicies.id, String(req.params.id)), eq(ztnaPolicies.orgId, orgId)));
      res.json({ message: "Policy deleted" });
    } catch (err) {
      log.error("Failed to delete ZTNA policy", { error: String(err) });
      res.status(500).json({ message: "Failed to delete ZTNA policy" });
    }
  });

  /** Evaluate ZTNA access for a device */
  app.post(
    "/api/mobile/ztna/evaluate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { deviceId, country, ipAddress, isOffHours } = req.body;

        if (!deviceId) {
          return res.status(400).json({ message: "deviceId is required" });
        }

        const [device] = await db
          .select()
          .from(mobileDevices)
          .where(and(eq(mobileDevices.id, deviceId), eq(mobileDevices.orgId, orgId)));
        if (!device) return res.status(404).json({ message: "Device not found" });

        // Load all enabled policies sorted by priority
        const policies = await db
          .select()
          .from(ztnaPolicies)
          .where(and(eq(ztnaPolicies.orgId, orgId), eq(ztnaPolicies.enabled, true)))
          .orderBy(ztnaPolicies.priority);

        let decision: string = "allow";
        let matchedPolicy: string | null = null;
        const violations: string[] = [];

        for (const policy of policies) {
          // Check platform
          const allowedPlatforms = policy.allowedPlatforms as string[] | null;
          if (allowedPlatforms && !allowedPlatforms.includes(device.platform)) {
            decision = policy.action;
            matchedPolicy = policy.id;
            violations.push(`Platform ${device.platform} not in allowed list`);
            break;
          }

          // Check rooted/jailbroken
          if (policy.blockRooted && (device.isRooted || device.isJailbroken)) {
            decision = "deny";
            matchedPolicy = policy.id;
            violations.push("Device is rooted/jailbroken");
            break;
          }

          // Check encryption
          if (policy.requireEncryption && !device.isEncrypted) {
            decision = policy.action;
            matchedPolicy = policy.id;
            violations.push("Device not encrypted");
            break;
          }

          // Check MDM
          if (policy.requireMdm && !device.hasMdm) {
            decision = policy.action;
            matchedPolicy = policy.id;
            violations.push("Device not enrolled in MDM");
            break;
          }

          // Check screen lock
          if (policy.requireScreenLock && !device.hasScreenLock) {
            decision = policy.action;
            matchedPolicy = policy.id;
            violations.push("No screen lock configured");
            break;
          }

          // Check risk score
          if (policy.maxRiskScore != null && device.riskScore > policy.maxRiskScore) {
            decision = policy.action;
            matchedPolicy = policy.id;
            violations.push(`Risk score ${device.riskScore} exceeds max ${policy.maxRiskScore}`);
            break;
          }

          // Check blocked countries
          const blockedCountries = policy.blockedCountries as string[] | null;
          if (country && blockedCountries && blockedCountries.includes(country)) {
            decision = "deny";
            matchedPolicy = policy.id;
            violations.push(`Country ${country} is blocked`);
            break;
          }

          // Check allowed countries
          const allowedCountries = policy.allowedCountries as string[] | null;
          if (country && allowedCountries && !allowedCountries.includes(country)) {
            decision = policy.action;
            matchedPolicy = policy.id;
            violations.push(`Country ${country} not in allowed list`);
            break;
          }

          // Check MFA requirement
          if (policy.requireMfa) {
            violations.push("Step-up MFA required");
            decision = "step-up-mfa";
            matchedPolicy = policy.id;
            break;
          }
        }

        res.json({
          decision,
          matchedPolicyId: matchedPolicy,
          violations,
          device: {
            id: device.id,
            name: device.deviceName,
            platform: device.platform,
            complianceStatus: device.complianceStatus,
            riskScore: device.riskScore,
            riskLevel: device.riskLevel,
          },
        });
      } catch (err) {
        log.error("Failed to evaluate ZTNA access", { error: String(err) });
        res.status(500).json({ message: "Failed to evaluate ZTNA" });
      }
    },
  );

  // =========================================================================
  // REMOTE WORKER SESSIONS
  // =========================================================================

  /** List remote worker sessions */
  app.get("/api/mobile/sessions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const active = req.query.active === "true";

      const conditions = [eq(remoteWorkerSessions.orgId, orgId)];
      if (active) {
        conditions.push(isNull(remoteWorkerSessions.sessionEnd));
      }

      const sessions = await db
        .select()
        .from(remoteWorkerSessions)
        .where(and(...conditions))
        .orderBy(desc(remoteWorkerSessions.sessionStart))
        .limit(500);
      res.json(sessions);
    } catch (err) {
      log.error("Failed to list remote sessions", { error: String(err) });
      res.status(500).json({ message: "Failed to list remote sessions" });
    }
  });

  /** Create/start a remote worker session */
  app.post(
    "/api/mobile/sessions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { userId, deviceId, ipAddress, country, city, vpnConnected, vpnProvider, isOffHours, isNewLocation } =
          req.body;

        if (!userId) {
          return res.status(400).json({ message: "userId is required" });
        }

        // Verify device belongs to org if provided
        if (deviceId) {
          const [device] = await db
            .select()
            .from(mobileDevices)
            .where(and(eq(mobileDevices.id, deviceId), eq(mobileDevices.orgId, orgId)));
          if (!device) return res.status(400).json({ message: "Device not found in org" });
        }

        const riskData = computeSessionRiskScore({
          vpnConnected,
          isOffHours,
          isNewLocation,
          country,
        });

        const [session] = await db
          .insert(remoteWorkerSessions)
          .values({
            orgId,
            userId,
            deviceId: deviceId || null,
            ipAddress: ipAddress || null,
            country: country || null,
            city: city || null,
            vpnConnected: vpnConnected === true,
            vpnProvider: vpnProvider || null,
            isOffHours: isOffHours === true,
            isNewLocation: isNewLocation === true,
            riskScore: riskData.score,
            riskFactors: riskData.factors as unknown as Record<string, unknown>,
          })
          .returning();

        // Create alert for high-risk sessions
        if (riskData.score >= 50) {
          await createAlertAndPublish({
            orgId,
            source: "mobile_mtd",
            category: "anomaly",
            severity: riskData.score >= 75 ? "high" : "medium",
            title: `[Remote Worker] High-risk session detected`,
            description: `Risk factors: ${riskData.factors.join(", ")}. User: ${userId}, IP: ${ipAddress || "unknown"}, Country: ${country || "unknown"}`,
            sourceIp: ipAddress || null,
            status: "new",
            rawData: { sessionId: session.id, riskScore: riskData.score, riskFactors: riskData.factors } as Record<
              string,
              unknown
            >,
            detectedAt: new Date(),
          });
        }

        res.status(201).json(session);
      } catch (err) {
        log.error("Failed to create remote session", { error: String(err) });
        res.status(500).json({ message: "Failed to create remote session" });
      }
    },
  );

  /** End a remote worker session */
  app.patch(
    "/api/mobile/sessions/:id/end",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(remoteWorkerSessions)
          .where(and(eq(remoteWorkerSessions.id, String(req.params.id)), eq(remoteWorkerSessions.orgId, orgId)));
        if (!existing) return res.status(404).json({ message: "Session not found" });

        const [updated] = await db
          .update(remoteWorkerSessions)
          .set({ sessionEnd: new Date() } as typeof remoteWorkerSessions.$inferInsert)
          .where(eq(remoteWorkerSessions.id, existing.id))
          .returning();
        res.json(updated);
      } catch (err) {
        log.error("Failed to end remote session", { error: String(err) });
        res.status(500).json({ message: "Failed to end remote session" });
      }
    },
  );

  // =========================================================================
  // MDM INTEGRATIONS CONFIG
  // =========================================================================

  /** Get MDM integration status */
  app.get("/api/mobile/mdm/status", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Count devices by MDM provider
      const byProvider = await db
        .select({
          mdmProvider: mobileDevices.mdmProvider,
          count: count(),
        })
        .from(mobileDevices)
        .where(eq(mobileDevices.orgId, orgId))
        .groupBy(mobileDevices.mdmProvider);

      const providers = [
        {
          provider: "jamf",
          label: "Jamf Pro",
          description: "Apple device management for macOS, iOS, iPadOS, tvOS",
          configured: false,
          deviceCount: 0,
          supportedPlatforms: ["ios", "macos"],
        },
        {
          provider: "intune",
          label: "Microsoft Intune",
          description: "Cross-platform endpoint management via Microsoft Graph API",
          configured: false,
          deviceCount: 0,
          supportedPlatforms: ["ios", "android", "windows", "macos"],
        },
        {
          provider: "workspace-one",
          label: "VMware Workspace ONE",
          description: "Digital workspace platform for unified endpoint management",
          configured: false,
          deviceCount: 0,
          supportedPlatforms: ["ios", "android", "windows", "macos", "chromeos"],
        },
      ];

      for (const entry of byProvider) {
        const p = providers.find((pr) => pr.provider === entry.mdmProvider);
        if (p) {
          p.configured = true;
          p.deviceCount = Number(entry.count);
        }
      }

      res.json(providers);
    } catch (err) {
      log.error("Failed to get MDM status", { error: String(err) });
      res.status(500).json({ message: "Failed to get MDM status" });
    }
  });

  // =========================================================================
  // 56.4 — MDM INTEGRATION VALIDATION
  // =========================================================================

  /** Validate MDM integration actually syncs real device data */
  app.get("/api/mobile/mdm/validate", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Check devices grouped by MDM provider
      const byProvider = await db
        .select({
          mdmProvider: mobileDevices.mdmProvider,
          count: count(),
        })
        .from(mobileDevices)
        .where(and(eq(mobileDevices.orgId, orgId), sql`${mobileDevices.mdmProvider} IS NOT NULL`))
        .groupBy(mobileDevices.mdmProvider);

      // For each configured provider, validate data freshness & completeness
      const providerValidation = [
        { provider: "jamf", label: "Jamf Pro", expectedFields: ["serialNumber", "osVersion", "model"] },
        {
          provider: "intune",
          label: "Microsoft Intune",
          expectedFields: ["serialNumber", "osVersion", "model", "isEncrypted"],
        },
        {
          provider: "workspace-one",
          label: "VMware Workspace ONE",
          expectedFields: ["serialNumber", "osVersion", "isEncrypted", "hasScreenLock"],
        },
      ];

      const results = [];

      for (const pv of providerValidation) {
        const providerRow = byProvider.find((b) => b.mdmProvider === pv.provider);
        const deviceCount = Number(providerRow?.count || 0);

        if (deviceCount === 0) {
          results.push({
            provider: pv.provider,
            label: pv.label,
            configured: false,
            deviceCount: 0,
            dataFreshness: null,
            missingFields: [],
            isUsingRealData: false,
            validationStatus: "not_configured",
            recommendations: ["Connect your MDM to start syncing device inventory"],
          });
          continue;
        }

        // Check data freshness — how recently were devices updated?
        const [freshness] = await db
          .select({
            newest: sql<string>`MAX(${mobileDevices.lastCheckIn})`,
            oldest: sql<string>`MIN(${mobileDevices.lastCheckIn})`,
          })
          .from(mobileDevices)
          .where(and(eq(mobileDevices.orgId, orgId), eq(mobileDevices.mdmProvider, pv.provider)));

        // Check for missing critical fields (indicator of simulated data)
        const missingFields: string[] = [];
        const [sample] = await db
          .select()
          .from(mobileDevices)
          .where(and(eq(mobileDevices.orgId, orgId), eq(mobileDevices.mdmProvider, pv.provider)))
          .limit(1);

        if (sample) {
          const sampleRecord = sample as Record<string, unknown>;
          for (const field of pv.expectedFields) {
            if (sampleRecord[field] === null || sampleRecord[field] === undefined || sampleRecord[field] === "") {
              missingFields.push(field);
            }
          }
        }

        const newestDate = freshness.newest ? new Date(freshness.newest) : null;
        const staleThreshold = 24 * 60 * 60 * 1000; // 24 hours
        const isStale = newestDate ? Date.now() - newestDate.getTime() > staleThreshold : true;
        const isUsingRealData = missingFields.length === 0 && !isStale;

        const recommendations: string[] = [];
        if (isStale) recommendations.push("Device check-in data is stale (>24h) — verify MDM sync schedule");
        if (missingFields.length > 0)
          recommendations.push(`Missing fields: ${missingFields.join(", ")} — verify API permissions`);
        if (!isUsingRealData)
          recommendations.push("Posture checks may be using incomplete data — review MDM integration");

        results.push({
          provider: pv.provider,
          label: pv.label,
          configured: true,
          deviceCount,
          dataFreshness: newestDate ? newestDate.toISOString() : null,
          isStale,
          missingFields,
          isUsingRealData,
          validationStatus: isUsingRealData ? "healthy" : isStale ? "stale" : "incomplete",
          recommendations,
        });
      }

      const allHealthy = results.every((r) => !r.configured || r.validationStatus === "healthy");
      res.json({
        providers: results,
        overallStatus: allHealthy ? "healthy" : "needs_attention",
        summary: `${results.filter((r) => r.configured).length}/${results.length} providers configured, ${results.filter((r) => r.isUsingRealData).length} using real data`,
      });
    } catch (err) {
      log.error("Failed to validate MDM integration", { error: String(err) });
      res.status(500).json({ message: "Failed to validate MDM integration" });
    }
  });

  // =========================================================================
  // 56.5 — APP RISK ANALYSIS
  // =========================================================================

  /** Analyze installed apps on managed devices for risk */
  app.get("/api/mobile/app-risk", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Known-malicious and dangerous-permission app patterns
      const MALICIOUS_PATTERNS = [
        { pattern: /^com\.hack/i, reason: "Known hacking tool package" },
        { pattern: /^com\.spy/i, reason: "Potential spyware" },
        { pattern: /^com\.keylog/i, reason: "Keylogger detected" },
        { pattern: /^com\.exploit/i, reason: "Exploit toolkit" },
        { pattern: /xhelper/i, reason: "Known malware family: xHelper" },
        { pattern: /joker/i, reason: "Known malware family: Joker" },
        { pattern: /hiddad/i, reason: "Known malware family: HiddAd" },
      ];

      const DANGEROUS_PERMISSIONS = [
        "CAMERA",
        "RECORD_AUDIO",
        "READ_CONTACTS",
        "ACCESS_FINE_LOCATION",
        "READ_SMS",
        "SEND_SMS",
        "READ_CALL_LOG",
        "SYSTEM_ALERT_WINDOW",
        "BIND_ACCESSIBILITY_SERVICE",
        "BIND_DEVICE_ADMIN",
      ];

      const devices = await db
        .select({
          id: mobileDevices.id,
          deviceName: mobileDevices.deviceName,
          platform: mobileDevices.platform,
          installedApps: mobileDevices.installedApps,
          sideloadedApps: mobileDevices.sideloadedApps,
        })
        .from(mobileDevices)
        .where(eq(mobileDevices.orgId, orgId));

      const flaggedApps: Array<{
        deviceId: string;
        deviceName: string;
        appName: string;
        appPackage: string;
        riskLevel: string;
        reasons: string[];
        isSideloaded: boolean;
      }> = [];

      let totalAppsScanned = 0;

      for (const device of devices) {
        const installed = Array.isArray(device.installedApps) ? device.installedApps : [];
        const sideloaded = Array.isArray(device.sideloadedApps) ? device.sideloadedApps : [];
        const sideloadedSet = new Set(sideloaded.map((s: unknown) => String(s)));

        for (const app of installed) {
          totalAppsScanned++;
          const appStr = String(app);
          const reasons: string[] = [];

          // Check against known-malicious patterns
          for (const mal of MALICIOUS_PATTERNS) {
            if (mal.pattern.test(appStr)) {
              reasons.push(mal.reason);
            }
          }

          // Flag sideloaded apps
          const isSideloaded = sideloadedSet.has(appStr);
          if (isSideloaded) {
            reasons.push("App installed from unknown source (sideloaded)");
          }

          if (reasons.length > 0) {
            const riskLevel = reasons.some(
              (r) => r.includes("malware") || r.includes("Keylogger") || r.includes("spyware"),
            )
              ? "critical"
              : reasons.some((r) => r.includes("hacking") || r.includes("Exploit"))
                ? "high"
                : isSideloaded
                  ? "medium"
                  : "low";

            flaggedApps.push({
              deviceId: device.id,
              deviceName: device.deviceName,
              appName: appStr.split(".").pop() || appStr,
              appPackage: appStr,
              riskLevel,
              reasons,
              isSideloaded,
            });
          }
        }
      }

      // Sort by risk level
      const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      flaggedApps.sort((a, b) => (riskOrder[a.riskLevel] ?? 4) - (riskOrder[b.riskLevel] ?? 4));

      res.json({
        totalDevicesScanned: devices.length,
        totalAppsScanned,
        flaggedApps,
        summary: {
          total: flaggedApps.length,
          critical: flaggedApps.filter((a) => a.riskLevel === "critical").length,
          high: flaggedApps.filter((a) => a.riskLevel === "high").length,
          medium: flaggedApps.filter((a) => a.riskLevel === "medium").length,
          low: flaggedApps.filter((a) => a.riskLevel === "low").length,
          sideloaded: flaggedApps.filter((a) => a.isSideloaded).length,
        },
        dangerousPermissions: DANGEROUS_PERMISSIONS,
      });
    } catch (err) {
      log.error("Failed to analyze app risk", { error: String(err) });
      res.status(500).json({ message: "Failed to analyze app risk" });
    }
  });

  // =========================================================================
  // DASHBOARD / STATISTICS
  // =========================================================================

  /** Get mobile security dashboard stats */
  app.get("/api/mobile/dashboard", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [totalDevices] = await db
        .select({ count: count() })
        .from(mobileDevices)
        .where(eq(mobileDevices.orgId, orgId));

      const byCompliance = await db
        .select({
          complianceStatus: mobileDevices.complianceStatus,
          count: count(),
        })
        .from(mobileDevices)
        .where(eq(mobileDevices.orgId, orgId))
        .groupBy(mobileDevices.complianceStatus);

      const byPlatform = await db
        .select({
          platform: mobileDevices.platform,
          count: count(),
        })
        .from(mobileDevices)
        .where(eq(mobileDevices.orgId, orgId))
        .groupBy(mobileDevices.platform);

      const byRisk = await db
        .select({
          riskLevel: mobileDevices.riskLevel,
          count: count(),
        })
        .from(mobileDevices)
        .where(eq(mobileDevices.orgId, orgId))
        .groupBy(mobileDevices.riskLevel);

      const [activeThreats] = await db
        .select({ count: count() })
        .from(mobileThreats)
        .where(and(eq(mobileThreats.orgId, orgId), eq(mobileThreats.status, "new")));

      const [activeSessions] = await db
        .select({ count: count() })
        .from(remoteWorkerSessions)
        .where(and(eq(remoteWorkerSessions.orgId, orgId), isNull(remoteWorkerSessions.sessionEnd)));

      const [totalPolicies] = await db
        .select({ count: count() })
        .from(ztnaPolicies)
        .where(eq(ztnaPolicies.orgId, orgId));

      const [rootedDevices] = await db
        .select({ count: count() })
        .from(mobileDevices)
        .where(
          and(
            eq(mobileDevices.orgId, orgId),
            sql`(${mobileDevices.isRooted} = true OR ${mobileDevices.isJailbroken} = true)`,
          ),
        );

      const [unencryptedDevices] = await db
        .select({ count: count() })
        .from(mobileDevices)
        .where(and(eq(mobileDevices.orgId, orgId), eq(mobileDevices.isEncrypted, false)));

      const [noMdmDevices] = await db
        .select({ count: count() })
        .from(mobileDevices)
        .where(and(eq(mobileDevices.orgId, orgId), eq(mobileDevices.hasMdm, false)));

      const recentThreats = await db
        .select()
        .from(mobileThreats)
        .where(eq(mobileThreats.orgId, orgId))
        .orderBy(desc(mobileThreats.detectedAt))
        .limit(10);

      // Compute overall fleet compliance score
      const totalCount = Number(totalDevices.count);
      const compliantCount = byCompliance.find((c) => c.complianceStatus === "compliant")?.count || 0;
      const complianceRate = totalCount > 0 ? Math.round((Number(compliantCount) / totalCount) * 100) : 0;

      res.json({
        totalDevices: totalCount,
        complianceRate,
        byCompliance,
        byPlatform,
        byRisk,
        activeThreats: Number(activeThreats.count),
        activeSessions: Number(activeSessions.count),
        totalPolicies: Number(totalPolicies.count),
        rootedDevices: Number(rootedDevices.count),
        unencryptedDevices: Number(unencryptedDevices.count),
        noMdmDevices: Number(noMdmDevices.count),
        recentThreats,
      });
    } catch (err) {
      log.error("Failed to get mobile dashboard", { error: String(err) });
      res.status(500).json({ message: "Failed to get mobile dashboard" });
    }
  });
}
