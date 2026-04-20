import type { Express } from "express";
import { eq, and, desc, sql, count, gte, isNull } from "drizzle-orm";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { db } from "../db";
import {
  otAssets,
  otConnections,
  otAnomalies,
  industrialProtocolEvents,
  alerts,
  OT_ASSET_TYPES,
  OT_PROTOCOLS,
  PURDUE_LEVELS,
  OT_ANOMALY_TYPES,
  OT_ANOMALY_SEVERITIES,
} from "@shared/schema";
import {
  classifyAssetPurdueLevel,
  crossesBoundary,
  getAllPurdueLevels,
  matchThreatSignatures,
  OT_THREAT_SIGNATURES,
} from "../ot-protocol-parser";

const log = logger.child("ot-security");

const ALLOWED_ASSET_TYPES = OT_ASSET_TYPES as readonly string[];
const ALLOWED_PROTOCOLS = OT_PROTOCOLS as readonly string[];
const ALLOWED_PURDUE_LEVELS = PURDUE_LEVELS as readonly string[];
const ALLOWED_ANOMALY_TYPES = OT_ANOMALY_TYPES as readonly string[];
const ALLOWED_ANOMALY_SEVERITIES = OT_ANOMALY_SEVERITIES as readonly string[];

export function registerOtSecurityRoutes(app: Express): void {
  // =========================================================================
  // OT ASSETS
  // =========================================================================

  /** List all OT assets for the org */
  app.get("/api/ot/assets", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await db
        .select()
        .from(otAssets)
        .where(eq(otAssets.orgId, orgId))
        .orderBy(desc(otAssets.updatedAt));
      res.json(assets);
    } catch (err) {
      log.error("Failed to list OT assets", { error: String(err) });
      res.status(500).json({ message: "Failed to list OT assets" });
    }
  });

  /** Get a single OT asset */
  app.get("/api/ot/assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(otAssets)
        .where(and(eq(otAssets.id, req.params.id as string), eq(otAssets.orgId, orgId)));
      if (!asset) return res.status(404).json({ message: "OT asset not found" });
      res.json(asset);
    } catch (err) {
      log.error("Failed to get OT asset", { error: String(err) });
      res.status(500).json({ message: "Failed to get OT asset" });
    }
  });

  /** Create a new OT asset (manual registration) */
  app.post("/api/ot/assets", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const {
        name,
        description,
        assetType,
        ipAddress,
        macAddress,
        hostname,
        purdueLevel,
        zone,
        vendor,
        model,
        firmwareVersion,
        serialNumber,
        protocols,
        facility,
        area,
        line,
        isCritical,
        isSafetySystem,
        silRating,
        tags,
      } = req.body;

      if (!name || typeof name !== "string" || name.trim().length === 0) {
        return res.status(400).json({ message: "Name is required" });
      }
      if (!assetType || !ALLOWED_ASSET_TYPES.includes(assetType)) {
        return res.status(400).json({ message: `Invalid asset type. Allowed: ${ALLOWED_ASSET_TYPES.join(", ")}` });
      }
      if (purdueLevel && !ALLOWED_PURDUE_LEVELS.includes(purdueLevel)) {
        return res.status(400).json({ message: `Invalid Purdue level. Allowed: ${ALLOWED_PURDUE_LEVELS.join(", ")}` });
      }

      const effectivePurdueLevel = purdueLevel || classifyAssetPurdueLevel(assetType);

      const [asset] = await db
        .insert(otAssets)
        .values({
          orgId,
          name: name.trim(),
          description: description || null,
          assetType,
          ipAddress: ipAddress || null,
          macAddress: macAddress || null,
          hostname: hostname || null,
          purdueLevel: effectivePurdueLevel,
          zone: zone || null,
          vendor: vendor || null,
          model: model || null,
          firmwareVersion: firmwareVersion || null,
          serialNumber: serialNumber || null,
          protocols: protocols || null,
          facility: facility || null,
          area: area || null,
          line: line || null,
          status: "online",
          isCritical: isCritical === true,
          isSafetySystem: isSafetySystem === true,
          silRating: silRating || null,
          tags: tags || null,
          discoveredBy: "manual",
          firstSeen: new Date(),
          lastSeen: new Date(),
        })
        .returning();

      log.info(`OT asset created: ${asset.name} (${asset.assetType}) in org ${orgId}`);
      res.status(201).json(asset);
    } catch (err) {
      log.error("Failed to create OT asset", { error: String(err) });
      res.status(500).json({ message: "Failed to create OT asset" });
    }
  });

  /** Update an OT asset */
  app.patch("/api/ot/assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(otAssets)
        .where(and(eq(otAssets.id, req.params.id as string), eq(otAssets.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "OT asset not found" });

      const allowedFields = [
        "name",
        "description",
        "assetType",
        "ipAddress",
        "macAddress",
        "hostname",
        "purdueLevel",
        "zone",
        "vendor",
        "model",
        "firmwareVersion",
        "serialNumber",
        "hardwareRevision",
        "protocols",
        "facility",
        "area",
        "line",
        "status",
        "isCritical",
        "isSafetySystem",
        "isManaged",
        "silRating",
        "tags",
        "metadata",
      ];
      const updates: Record<string, unknown> = { updatedAt: new Date() };
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (updates.assetType && !ALLOWED_ASSET_TYPES.includes(updates.assetType as string)) {
        return res.status(400).json({ message: "Invalid asset type" });
      }
      if (updates.purdueLevel && !ALLOWED_PURDUE_LEVELS.includes(updates.purdueLevel as string)) {
        return res.status(400).json({ message: "Invalid Purdue level" });
      }

      const [updated] = await db
        .update(otAssets)
        .set(updates as Record<string, unknown> as typeof otAssets.$inferInsert)
        .where(and(eq(otAssets.id, req.params.id as string), eq(otAssets.orgId, orgId)))
        .returning();
      res.json(updated);
    } catch (err) {
      log.error("Failed to update OT asset", { error: String(err) });
      res.status(500).json({ message: "Failed to update OT asset" });
    }
  });

  /** Delete an OT asset */
  app.delete("/api/ot/assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(otAssets)
        .where(and(eq(otAssets.id, req.params.id as string), eq(otAssets.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "OT asset not found" });

      await db.delete(otAssets).where(and(eq(otAssets.id, req.params.id as string), eq(otAssets.orgId, orgId)));
      res.json({ message: "OT asset deleted" });
    } catch (err) {
      log.error("Failed to delete OT asset", { error: String(err) });
      res.status(500).json({ message: "Failed to delete OT asset" });
    }
  });

  // =========================================================================
  // OT CONNECTIONS
  // =========================================================================

  /** List OT connections */
  app.get("/api/ot/connections", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const boundaryOnly = req.query.boundary === "true";

      const query = db
        .select()
        .from(otConnections)
        .where(
          boundaryOnly
            ? and(eq(otConnections.orgId, orgId), eq(otConnections.crossesBoundary, true))
            : eq(otConnections.orgId, orgId),
        )
        .orderBy(desc(otConnections.lastActivity))
        .$dynamic();

      const connections = await query;
      res.json(connections);
    } catch (err) {
      log.error("Failed to list OT connections", { error: String(err) });
      res.status(500).json({ message: "Failed to list OT connections" });
    }
  });

  /** Create/register an OT connection */
  app.post("/api/ot/connections", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { sourceAssetId, destAssetId, sourceIp, destIp, sourcePort, destPort, protocol, isAllowed, ruleId } =
        req.body;

      // Determine Purdue levels from assets
      let sourcePurdueLevel: string | null = null;
      let destPurdueLevel: string | null = null;

      if (sourceAssetId) {
        const [src] = await db
          .select()
          .from(otAssets)
          .where(and(eq(otAssets.id, sourceAssetId), eq(otAssets.orgId, orgId)));
        if (!src) return res.status(400).json({ message: "Source asset not found" });
        sourcePurdueLevel = src.purdueLevel;
      }

      if (destAssetId) {
        const [dst] = await db
          .select()
          .from(otAssets)
          .where(and(eq(otAssets.id, destAssetId), eq(otAssets.orgId, orgId)));
        if (!dst) return res.status(400).json({ message: "Destination asset not found" });
        destPurdueLevel = dst.purdueLevel;
      }

      const isBoundaryCrossing =
        sourcePurdueLevel && destPurdueLevel ? crossesBoundary(sourcePurdueLevel, destPurdueLevel) : false;

      const [connection] = await db
        .insert(otConnections)
        .values({
          orgId,
          sourceAssetId: sourceAssetId || null,
          destAssetId: destAssetId || null,
          sourceIp: sourceIp || null,
          destIp: destIp || null,
          sourcePort: sourcePort ? parseInt(sourcePort, 10) : null,
          destPort: destPort ? parseInt(destPort, 10) : null,
          protocol: protocol || null,
          sourcePurdueLevel,
          destPurdueLevel,
          crossesBoundary: isBoundaryCrossing,
          isAllowed: isAllowed !== false,
          ruleId: ruleId || null,
          lastActivity: new Date(),
        })
        .returning();

      res.status(201).json(connection);
    } catch (err) {
      log.error("Failed to create OT connection", { error: String(err) });
      res.status(500).json({ message: "Failed to create OT connection" });
    }
  });

  // =========================================================================
  // OT ANOMALIES
  // =========================================================================

  /** List OT anomalies */
  app.get("/api/ot/anomalies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const severity = req.query.severity as string | undefined;

      const conditions = [eq(otAnomalies.orgId, orgId)];
      if (status) conditions.push(eq(otAnomalies.status, status));
      if (severity) conditions.push(eq(otAnomalies.severity, severity));

      const anomalies = await db
        .select()
        .from(otAnomalies)
        .where(and(...conditions))
        .orderBy(desc(otAnomalies.detectedAt))
        .limit(500);
      res.json(anomalies);
    } catch (err) {
      log.error("Failed to list OT anomalies", { error: String(err) });
      res.status(500).json({ message: "Failed to list OT anomalies" });
    }
  });

  /** Create an OT anomaly (from sensor or manual report) */
  app.post("/api/ot/anomalies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const {
        assetId,
        connectionId,
        anomalyType,
        severity,
        title,
        description,
        protocol,
        functionCode,
        registerAddress,
        previousValue,
        newValue,
        sourceIp,
        destIp,
        sourcePort,
        destPort,
        icsCertAdvisory,
        mitreTactic,
        mitreTechnique,
        metadata,
      } = req.body;

      if (!title || typeof title !== "string") {
        return res.status(400).json({ message: "Title is required" });
      }
      if (!anomalyType || !ALLOWED_ANOMALY_TYPES.includes(anomalyType)) {
        return res.status(400).json({ message: "Invalid anomaly type" });
      }
      if (severity && !ALLOWED_ANOMALY_SEVERITIES.includes(severity)) {
        return res.status(400).json({ message: "Invalid severity" });
      }

      // Verify asset belongs to org
      if (assetId) {
        const [asset] = await db
          .select()
          .from(otAssets)
          .where(and(eq(otAssets.id, assetId), eq(otAssets.orgId, orgId)));
        if (!asset) return res.status(400).json({ message: "Asset not found in org" });
      }

      // Create the anomaly
      const [anomaly] = await db
        .insert(otAnomalies)
        .values({
          orgId,
          assetId: assetId || null,
          connectionId: connectionId || null,
          anomalyType,
          severity: severity || "high",
          title,
          description: description || null,
          protocol: protocol || null,
          functionCode: functionCode != null ? parseInt(String(functionCode), 10) : null,
          registerAddress: registerAddress != null ? parseInt(String(registerAddress), 10) : null,
          previousValue: previousValue || null,
          newValue: newValue || null,
          sourceIp: sourceIp || null,
          destIp: destIp || null,
          sourcePort: sourcePort != null ? parseInt(String(sourcePort), 10) : null,
          destPort: destPort != null ? parseInt(String(destPort), 10) : null,
          icsCertAdvisory: icsCertAdvisory || null,
          mitreTactic: mitreTactic || null,
          mitreTechnique: mitreTechnique || null,
          metadata: (metadata || null) as Record<string, unknown> | null,
          status: "new",
        })
        .returning();

      // Auto-create an alert for critical/high anomalies
      if (anomaly.severity === "critical" || anomaly.severity === "high") {
        const [alert] = await db
          .insert(alerts)
          .values({
            orgId,
            source: "ot_ics",
            category: "intrusion",
            severity: anomaly.severity,
            title: `[OT/ICS] ${anomaly.title}`,
            description: anomaly.description || `OT anomaly detected: ${anomaly.anomalyType}`,
            sourceIp: anomaly.sourceIp,
            status: "new",
            mitreTactic: anomaly.mitreTactic,
            mitreTechnique: anomaly.mitreTechnique,
            rawData: { otAnomalyId: anomaly.id, anomalyType: anomaly.anomalyType } as Record<string, unknown>,
            detectedAt: new Date(),
          })
          .returning();

        // Link alert back to anomaly
        await db.update(otAnomalies).set({ alertId: alert.id }).where(eq(otAnomalies.id, anomaly.id));
      }

      res.status(201).json(anomaly);
    } catch (err) {
      log.error("Failed to create OT anomaly", { error: String(err) });
      res.status(500).json({ message: "Failed to create OT anomaly" });
    }
  });

  /** Update anomaly status (resolve, investigate, etc.) */
  app.patch("/api/ot/anomalies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(otAnomalies)
        .where(and(eq(otAnomalies.id, req.params.id as string), eq(otAnomalies.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "Anomaly not found" });

      const allowedFields = ["status", "resolvedBy", "resolvedAt", "metadata"];
      const updates: Record<string, unknown> = {};
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (updates.status === "resolved") {
        updates.resolvedAt = new Date();
      }

      const [updated] = await db
        .update(otAnomalies)
        .set(updates as Record<string, unknown> as typeof otAnomalies.$inferInsert)
        .where(and(eq(otAnomalies.id, req.params.id as string), eq(otAnomalies.orgId, orgId)))
        .returning();
      res.json(updated);
    } catch (err) {
      log.error("Failed to update OT anomaly", { error: String(err) });
      res.status(500).json({ message: "Failed to update OT anomaly" });
    }
  });

  // =========================================================================
  // PROTOCOL EVENTS
  // =========================================================================

  /** List industrial protocol events */
  app.get("/api/ot/protocol-events", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const protocolFilter = req.query.protocol as string | undefined;
      const writesOnly = req.query.writes === "true";
      const anomalousOnly = req.query.anomalous === "true";
      const limitParam = Math.min(parseInt(String(req.query.limit || "200"), 10) || 200, 1000);

      const conditions = [eq(industrialProtocolEvents.orgId, orgId)];
      if (protocolFilter) conditions.push(eq(industrialProtocolEvents.protocol, protocolFilter));
      if (writesOnly) conditions.push(eq(industrialProtocolEvents.isWrite, true));
      if (anomalousOnly) conditions.push(eq(industrialProtocolEvents.isAnomalous, true));

      const events = await db
        .select()
        .from(industrialProtocolEvents)
        .where(and(...conditions))
        .orderBy(desc(industrialProtocolEvents.capturedAt))
        .limit(limitParam);
      res.json(events);
    } catch (err) {
      log.error("Failed to list protocol events", { error: String(err) });
      res.status(500).json({ message: "Failed to list protocol events" });
    }
  });

  /** Ingest protocol events from OT sensor */
  app.post("/api/ot/protocol-events", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = Array.isArray(req.body) ? req.body : [req.body];

      if (events.length > 1000) {
        return res.status(400).json({ message: "Maximum 1000 events per batch" });
      }

      const inserted = [];
      for (const evt of events) {
        const {
          assetId,
          protocol,
          functionCode,
          functionName,
          sourceIp,
          destIp,
          sourcePort,
          destPort,
          registerAddress,
          registerCount,
          writeValue,
          readValue,
          unitId,
          isWrite,
          rawData,
        } = evt;

        if (!protocol || !ALLOWED_PROTOCOLS.includes(protocol)) continue;

        // Verify asset belongs to org if provided
        if (assetId) {
          const [asset] = await db
            .select()
            .from(otAssets)
            .where(and(eq(otAssets.id, assetId), eq(otAssets.orgId, orgId)));
          if (!asset) continue;
        }

        const [record] = await db
          .insert(industrialProtocolEvents)
          .values({
            orgId,
            assetId: assetId || null,
            protocol,
            functionCode: functionCode != null ? parseInt(String(functionCode), 10) : null,
            functionName: functionName || null,
            sourceIp: sourceIp || null,
            destIp: destIp || null,
            sourcePort: sourcePort != null ? parseInt(String(sourcePort), 10) : null,
            destPort: destPort != null ? parseInt(String(destPort), 10) : null,
            registerAddress: registerAddress != null ? parseInt(String(registerAddress), 10) : null,
            registerCount: registerCount != null ? parseInt(String(registerCount), 10) : null,
            writeValue: writeValue || null,
            readValue: readValue || null,
            unitId: unitId != null ? parseInt(String(unitId), 10) : null,
            isWrite: isWrite === true,
            isAnomalous: false,
            rawData: (rawData || null) as Record<string, unknown> | null,
          })
          .returning();

        inserted.push(record);
      }

      res.status(201).json({ inserted: inserted.length });
    } catch (err) {
      log.error("Failed to ingest protocol events", { error: String(err) });
      res.status(500).json({ message: "Failed to ingest protocol events" });
    }
  });

  // =========================================================================
  // PURDUE MODEL / TOPOLOGY
  // =========================================================================

  /** Get Purdue Model topology — assets grouped by level */
  app.get("/api/ot/topology", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const assets = await db
        .select()
        .from(otAssets)
        .where(eq(otAssets.orgId, orgId))
        .orderBy(otAssets.purdueLevel, otAssets.name);

      const connections = await db.select().from(otConnections).where(eq(otConnections.orgId, orgId));

      const levels = getAllPurdueLevels();

      const topology = levels.map((level) => ({
        ...level,
        assets: assets.filter((a) => a.purdueLevel === level.level),
        assetCount: assets.filter((a) => a.purdueLevel === level.level).length,
      }));

      const boundaryCrossings = connections.filter((c) => c.crossesBoundary);

      res.json({
        levels: topology,
        connections,
        boundaryCrossings,
        totalAssets: assets.length,
        totalConnections: connections.length,
        boundaryCrossingCount: boundaryCrossings.length,
      });
    } catch (err) {
      log.error("Failed to get topology", { error: String(err) });
      res.status(500).json({ message: "Failed to get topology" });
    }
  });

  // =========================================================================
  // IT/OT BOUNDARY MONITORING
  // =========================================================================

  /** Get IT/OT boundary crossing alerts and stats */
  app.get("/api/ot/boundary", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const crossings = await db
        .select()
        .from(otConnections)
        .where(and(eq(otConnections.orgId, orgId), eq(otConnections.crossesBoundary, true)))
        .orderBy(desc(otConnections.lastActivity));

      const boundaryAnomalies = await db
        .select()
        .from(otAnomalies)
        .where(and(eq(otAnomalies.orgId, orgId), eq(otAnomalies.anomalyType, "it_ot_boundary_crossing")))
        .orderBy(desc(otAnomalies.detectedAt))
        .limit(100);

      res.json({
        crossings,
        anomalies: boundaryAnomalies,
        totalCrossings: crossings.length,
        allowedCrossings: crossings.filter((c) => c.isAllowed).length,
        blockedCrossings: crossings.filter((c) => !c.isAllowed).length,
      });
    } catch (err) {
      log.error("Failed to get boundary data", { error: String(err) });
      res.status(500).json({ message: "Failed to get boundary data" });
    }
  });

  // =========================================================================
  // THREAT SIGNATURES
  // =========================================================================

  /** Get all OT threat signatures */
  app.get("/api/ot/signatures", isAuthenticated, async (_req, res) => {
    try {
      const signatures = OT_THREAT_SIGNATURES.map((sig) => ({
        id: sig.id,
        name: sig.name,
        description: sig.description,
        protocol: sig.protocol,
        severity: sig.severity,
        mitreTactic: sig.mitreTactic,
        mitreTechnique: sig.mitreTechnique,
        icsCertAdvisory: sig.icsCertAdvisory || null,
      }));
      res.json(signatures);
    } catch (err) {
      log.error("Failed to get signatures", { error: String(err) });
      res.status(500).json({ message: "Failed to get signatures" });
    }
  });

  // =========================================================================
  // ICS-CERT ADVISORIES
  // =========================================================================

  /** Get ICS-CERT advisories (simulated feed) */
  app.get("/api/ot/advisories", isAuthenticated, async (_req, res) => {
    try {
      // In production, this would fetch from CISA ICS-CERT RSS feed
      // For now, return curated advisories relevant to common OT environments
      const advisories = [
        {
          id: "ICSA-25-001-01",
          title: "Siemens SIMATIC S7-1500 CPU — Improper Access Control",
          vendor: "Siemens",
          product: "SIMATIC S7-1500",
          severity: "critical",
          cvss: 9.8,
          cveIds: ["CVE-2025-0001"],
          description:
            "A vulnerability in the web server of SIMATIC S7-1500 CPUs could allow an unauthenticated attacker to execute arbitrary code.",
          affectedVersions: "< V3.1.2",
          mitigation: "Update to firmware version V3.1.2 or later. Restrict network access to port 443.",
          publishedAt: "2025-01-15T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-001-01",
        },
        {
          id: "ICSA-25-002-01",
          title: "Rockwell Automation ControlLogix — Remote Code Execution",
          vendor: "Rockwell Automation",
          product: "ControlLogix 5580",
          severity: "critical",
          cvss: 10.0,
          cveIds: ["CVE-2025-0042"],
          description:
            "A critical vulnerability in ControlLogix 5580 controllers allows remote code execution via crafted CIP messages.",
          affectedVersions: "V33.011 and prior",
          mitigation: "Apply patch V33.013. Segment the OT network per Purdue Model recommendations.",
          publishedAt: "2025-02-01T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-002-01",
        },
        {
          id: "ICSA-25-003-01",
          title: "Schneider Electric Modicon M340 — Authentication Bypass",
          vendor: "Schneider Electric",
          product: "Modicon M340",
          severity: "high",
          cvss: 8.6,
          cveIds: ["CVE-2025-0103"],
          description:
            "An authentication bypass vulnerability in Modbus communication allows unauthorized read/write operations to PLC registers.",
          affectedVersions: "All versions prior to V3.60",
          mitigation:
            "Update firmware to V3.60. Enable Modbus security features. Monitor for unauthorized Modbus write operations.",
          publishedAt: "2025-03-10T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-003-01",
        },
        {
          id: "ICSA-25-004-01",
          title: "ABB Ability Symphony Plus — Privilege Escalation",
          vendor: "ABB",
          product: "Ability Symphony Plus",
          severity: "high",
          cvss: 7.8,
          cveIds: ["CVE-2025-0200"],
          description:
            "A privilege escalation vulnerability in the DCS platform allows authenticated users to gain system-level access.",
          affectedVersions: "S+ Operations V3.0 to V3.3 SP2",
          mitigation: "Apply SP3 update. Implement least-privilege access for all operator accounts.",
          publishedAt: "2025-04-05T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-004-01",
        },
        {
          id: "ICSA-25-005-01",
          title: "Honeywell Experion PKS — Denial of Service",
          vendor: "Honeywell",
          product: "Experion PKS",
          severity: "high",
          cvss: 7.5,
          cveIds: ["CVE-2025-0301"],
          description:
            "A crafted OPC-UA message can crash the Experion PKS server, causing loss of visibility into the industrial process.",
          affectedVersions: "R520 and prior",
          mitigation: "Upgrade to R530. Deploy OPC-UA deep packet inspection at the DMZ firewall.",
          publishedAt: "2025-05-20T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-005-01",
        },
        {
          id: "ICSA-25-006-01",
          title: "Emerson DeltaV — Hard-Coded Credentials",
          vendor: "Emerson",
          product: "DeltaV DCS",
          severity: "critical",
          cvss: 9.1,
          cveIds: ["CVE-2025-0410"],
          description:
            "Hard-coded credentials in the DeltaV Operate OPC server allow unauthenticated remote access to process control data.",
          affectedVersions: "V14.3 and prior",
          mitigation: "Apply DeltaV V14.3.1 patch. Change all default credentials immediately.",
          publishedAt: "2025-06-12T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-006-01",
        },
        {
          id: "ICSA-25-007-01",
          title: "GE Vernova MarkVIe — Buffer Overflow in Firmware Update",
          vendor: "GE Vernova",
          product: "MarkVIe Controller",
          severity: "critical",
          cvss: 9.8,
          cveIds: ["CVE-2025-0522"],
          description:
            "A buffer overflow in the firmware update mechanism allows an attacker with network access to execute arbitrary code on the controller.",
          affectedVersions: "All versions prior to V06.05.07",
          mitigation: "Update to V06.05.07. Isolate controllers on a dedicated VLAN with strict ACLs.",
          publishedAt: "2025-07-03T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-007-01",
        },
        {
          id: "ICSA-25-008-01",
          title: "Yokogawa CENTUM VP — Path Traversal",
          vendor: "Yokogawa",
          product: "CENTUM VP",
          severity: "medium",
          cvss: 6.5,
          cveIds: ["CVE-2025-0615"],
          description:
            "A path traversal vulnerability in the web HMI allows authenticated users to read arbitrary files from the CENTUM VP server.",
          affectedVersions: "R6.09.00 and prior",
          mitigation: "Apply R6.10.00. Restrict web HMI access to authorized operator stations only.",
          publishedAt: "2025-08-18T00:00:00Z",
          url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-008-01",
        },
      ];

      res.json(advisories);
    } catch (err) {
      log.error("Failed to get advisories", { error: String(err) });
      res.status(500).json({ message: "Failed to get ICS-CERT advisories" });
    }
  });

  // =========================================================================
  // DASHBOARD STATS
  // =========================================================================

  /** Get OT/ICS dashboard statistics */
  app.get("/api/ot/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [totalAssets] = await db.select({ count: count() }).from(otAssets).where(eq(otAssets.orgId, orgId));

      const [criticalAssets] = await db
        .select({ count: count() })
        .from(otAssets)
        .where(and(eq(otAssets.orgId, orgId), eq(otAssets.isCritical, true)));

      const [safetySystemsCount] = await db
        .select({ count: count() })
        .from(otAssets)
        .where(and(eq(otAssets.orgId, orgId), eq(otAssets.isSafetySystem, true)));

      const [totalConnections] = await db
        .select({ count: count() })
        .from(otConnections)
        .where(eq(otConnections.orgId, orgId));

      const [boundaryCrossings] = await db
        .select({ count: count() })
        .from(otConnections)
        .where(and(eq(otConnections.orgId, orgId), eq(otConnections.crossesBoundary, true)));

      const [openAnomalies] = await db
        .select({ count: count() })
        .from(otAnomalies)
        .where(and(eq(otAnomalies.orgId, orgId), eq(otAnomalies.status, "new")));

      const [criticalAnomalies] = await db
        .select({ count: count() })
        .from(otAnomalies)
        .where(and(eq(otAnomalies.orgId, orgId), eq(otAnomalies.severity, "critical"), eq(otAnomalies.status, "new")));

      const assetsByType = await db
        .select({ assetType: otAssets.assetType, count: count() })
        .from(otAssets)
        .where(eq(otAssets.orgId, orgId))
        .groupBy(otAssets.assetType);

      const assetsByLevel = await db
        .select({ purdueLevel: otAssets.purdueLevel, count: count() })
        .from(otAssets)
        .where(eq(otAssets.orgId, orgId))
        .groupBy(otAssets.purdueLevel);

      const anomaliesBySeverity = await db
        .select({ severity: otAnomalies.severity, count: count() })
        .from(otAnomalies)
        .where(and(eq(otAnomalies.orgId, orgId), eq(otAnomalies.status, "new")))
        .groupBy(otAnomalies.severity);

      const protocolDistribution = await db
        .select({ protocol: industrialProtocolEvents.protocol, count: count() })
        .from(industrialProtocolEvents)
        .where(eq(industrialProtocolEvents.orgId, orgId))
        .groupBy(industrialProtocolEvents.protocol);

      res.json({
        totalAssets: totalAssets.count,
        criticalAssets: criticalAssets.count,
        safetySystems: safetySystemsCount.count,
        totalConnections: totalConnections.count,
        boundaryCrossings: boundaryCrossings.count,
        openAnomalies: openAnomalies.count,
        criticalAnomalies: criticalAnomalies.count,
        assetsByType,
        assetsByLevel,
        anomaliesBySeverity,
        protocolDistribution,
      });
    } catch (err) {
      log.error("Failed to get OT stats", { error: String(err) });
      res.status(500).json({ message: "Failed to get OT stats" });
    }
  });

  // =========================================================================
  // PASSIVE NETWORK MONITORING VERIFICATION
  // =========================================================================

  /**
   * Verify that all OT discovery and monitoring is strictly passive.
   * OT/ICS networks CANNOT tolerate active scanning — all discovery must
   * be via network tap / SPAN port based passive observation only.
   * This endpoint returns the monitoring mode verification status.
   */
  app.get("/api/ot/passive-monitoring-status", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get all assets and check their discovery method
      const assets = await db
        .select({
          id: otAssets.id,
          name: otAssets.name,
          discoveredBy: otAssets.discoveredBy,
          status: otAssets.status,
        })
        .from(otAssets)
        .where(eq(otAssets.orgId, orgId));

      // Categorize discovery methods
      const passiveMethods = ["network_tap", "span_port", "passive_fingerprint", "protocol_analysis", "manual", null];
      const activeProbeIndicators = ["active_scan", "nmap", "vulnerability_scan", "ping_sweep", "port_scan"];

      const passiveAssets = assets.filter((a) => {
        const method = a.discoveredBy?.toLowerCase() || "";
        return !activeProbeIndicators.some((probe) => method.includes(probe));
      });

      const activeViolations = assets.filter((a) => {
        const method = a.discoveredBy?.toLowerCase() || "";
        return activeProbeIndicators.some((probe) => method.includes(probe));
      });

      const isFullyPassive = activeViolations.length === 0;

      res.json({
        isFullyPassive,
        monitoringMode: isFullyPassive ? "passive_only" : "mixed_warning",
        totalAssets: assets.length,
        passiveDiscoveryCount: passiveAssets.length,
        activeViolationCount: activeViolations.length,
        activeViolations: activeViolations.map((a) => ({
          assetId: a.id,
          assetName: a.name,
          discoveryMethod: a.discoveredBy,
          recommendation:
            "Switch to passive discovery via network tap or SPAN port. Active probing can disrupt OT/ICS operations.",
        })),
        allowedMethods: passiveMethods.filter(Boolean),
        bannedMethods: activeProbeIndicators,
        guidelines: {
          principle: "All OT/ICS network monitoring MUST be strictly passive",
          reason: "Active scanning can crash PLCs, disrupt safety systems, and cause physical damage",
          implementation: [
            "Deploy network taps at key junction points",
            "Configure SPAN/mirror ports on managed switches",
            "Use protocol-aware passive fingerprinting",
            "NEVER send packets to OT devices for discovery",
            "NEVER run vulnerability scans against OT assets",
          ],
        },
      });
    } catch (err) {
      log.error("Failed to get passive monitoring status", { error: String(err) });
      res.status(500).json({ message: "Failed to get passive monitoring status" });
    }
  });

  // =========================================================================
  // OT VULNERABILITY TRACKING (ICS-CERT cross-reference)
  // =========================================================================

  /**
   * Cross-reference OT assets with ICS-CERT advisories to identify
   * which assets are affected by known vulnerabilities.
   * Tracks OT-specific vulns (PLCs, HMIs, SCADA) with patch availability.
   */
  app.get("/api/ot/vulnerability-tracking", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get all OT assets with vendor/model info
      const assets = await db.select().from(otAssets).where(eq(otAssets.orgId, orgId));

      // Advisory vendor/product matching database
      // In production this would pull from a real ICS-CERT feed
      const advisoryMatches: Array<{
        assetId: string;
        assetName: string;
        assetType: string;
        vendor: string | null;
        model: string | null;
        firmwareVersion: string | null;
        advisoryId: string;
        advisoryTitle: string;
        severity: string;
        cvss: number;
        cveIds: string[];
        patchAvailable: boolean;
        patchVersion: string | null;
        riskMitigation: string[];
      }> = [];

      // Known vendor-product → advisory mappings
      const vendorAdvisoryMap: Record<
        string,
        {
          advisoryId: string;
          title: string;
          severity: string;
          cvss: number;
          cveIds: string[];
          patchAvailable: boolean;
          patchVersion: string | null;
          mitigation: string[];
        }
      > = {
        siemens: {
          advisoryId: "ICSA-25-001-01",
          title: "Siemens SIMATIC S7-1500 CPU — Improper Access Control",
          severity: "critical",
          cvss: 9.8,
          cveIds: ["CVE-2025-0001"],
          patchAvailable: true,
          patchVersion: "V3.1.2",
          mitigation: [
            "Update firmware to V3.1.2",
            "Restrict network access to port 443",
            "Enable access control lists",
          ],
        },
        "rockwell automation": {
          advisoryId: "ICSA-25-002-01",
          title: "Rockwell Automation ControlLogix — Remote Code Execution",
          severity: "critical",
          cvss: 10.0,
          cveIds: ["CVE-2025-0042"],
          patchAvailable: true,
          patchVersion: "V33.013",
          mitigation: [
            "Apply patch V33.013",
            "Segment OT network per Purdue Model",
            "Monitor CIP traffic for anomalies",
          ],
        },
        "schneider electric": {
          advisoryId: "ICSA-25-003-01",
          title: "Schneider Electric Modicon M340 — Authentication Bypass",
          severity: "high",
          cvss: 8.6,
          cveIds: ["CVE-2025-0103"],
          patchAvailable: true,
          patchVersion: "V3.60",
          mitigation: [
            "Update firmware to V3.60",
            "Enable Modbus security features",
            "Monitor unauthorized Modbus writes",
          ],
        },
        abb: {
          advisoryId: "ICSA-25-004-01",
          title: "ABB Ability Symphony Plus — Privilege Escalation",
          severity: "high",
          cvss: 7.8,
          cveIds: ["CVE-2025-0200"],
          patchAvailable: true,
          patchVersion: "SP3",
          mitigation: ["Apply SP3 update", "Implement least-privilege access", "Review operator account permissions"],
        },
        honeywell: {
          advisoryId: "ICSA-25-005-01",
          title: "Honeywell Experion PKS — Denial of Service",
          severity: "high",
          cvss: 7.5,
          cveIds: ["CVE-2025-0301"],
          patchAvailable: true,
          patchVersion: "R530",
          mitigation: ["Upgrade to R530", "Deploy OPC-UA deep packet inspection", "Restrict network access to HMI"],
        },
        emerson: {
          advisoryId: "ICSA-25-006-01",
          title: "Emerson DeltaV — Hard-Coded Credentials",
          severity: "critical",
          cvss: 9.1,
          cveIds: ["CVE-2025-0410"],
          patchAvailable: true,
          patchVersion: "V14.3.1",
          mitigation: ["Apply V14.3.1 patch", "Change all default credentials", "Enable credential rotation"],
        },
        yokogawa: {
          advisoryId: "ICSA-25-008-01",
          title: "Yokogawa CENTUM VP — Path Traversal",
          severity: "medium",
          cvss: 6.5,
          cveIds: ["CVE-2025-0615"],
          patchAvailable: true,
          patchVersion: "R6.10.00",
          mitigation: ["Apply R6.10.00", "Restrict web HMI access", "Enable file access auditing"],
        },
      };

      // Cross-reference each asset against advisory database
      for (const asset of assets) {
        if (!asset.vendor) continue;
        const vendorKey = asset.vendor.toLowerCase();
        const advisory = vendorAdvisoryMap[vendorKey];
        if (advisory) {
          advisoryMatches.push({
            assetId: asset.id,
            assetName: asset.name,
            assetType: asset.assetType,
            vendor: asset.vendor,
            model: asset.model,
            firmwareVersion: asset.firmwareVersion,
            advisoryId: advisory.advisoryId,
            advisoryTitle: advisory.title,
            severity: advisory.severity,
            cvss: advisory.cvss,
            cveIds: advisory.cveIds,
            patchAvailable: advisory.patchAvailable,
            patchVersion: advisory.patchVersion,
            riskMitigation: advisory.mitigation,
          });
        }
      }

      // Summary statistics
      const criticalCount = advisoryMatches.filter((m) => m.severity === "critical").length;
      const highCount = advisoryMatches.filter((m) => m.severity === "high").length;
      const patchableCount = advisoryMatches.filter((m) => m.patchAvailable).length;

      res.json({
        affectedAssets: advisoryMatches,
        summary: {
          totalAffected: advisoryMatches.length,
          totalAssets: assets.length,
          criticalVulnerabilities: criticalCount,
          highVulnerabilities: highCount,
          patchAvailable: patchableCount,
          unpatchable: advisoryMatches.length - patchableCount,
          coveragePercent: assets.length > 0 ? Math.round((advisoryMatches.length / assets.length) * 100) : 0,
        },
      });
    } catch (err) {
      log.error("Failed to get vulnerability tracking", { error: String(err) });
      res.status(500).json({ message: "Failed to get OT vulnerability tracking" });
    }
  });

  // =========================================================================
  // SAFETY SYSTEM MONITORING (SIS/SIL)
  // =========================================================================

  /** Get safety system status */
  app.get("/api/ot/safety-systems", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const safetySystems = await db
        .select()
        .from(otAssets)
        .where(and(eq(otAssets.orgId, orgId), eq(otAssets.isSafetySystem, true)))
        .orderBy(otAssets.silRating, otAssets.name);

      // Get anomalies targeting safety systems
      const safetyAnomalies = await db
        .select()
        .from(otAnomalies)
        .where(and(eq(otAnomalies.orgId, orgId), eq(otAnomalies.anomalyType, "safety_system_bypass")))
        .orderBy(desc(otAnomalies.detectedAt))
        .limit(50);

      res.json({
        systems: safetySystems,
        anomalies: safetyAnomalies,
        totalSystems: safetySystems.length,
        systemsBySil: {
          sil4: safetySystems.filter((s) => s.silRating === "SIL 4").length,
          sil3: safetySystems.filter((s) => s.silRating === "SIL 3").length,
          sil2: safetySystems.filter((s) => s.silRating === "SIL 2").length,
          sil1: safetySystems.filter((s) => s.silRating === "SIL 1").length,
        },
      });
    } catch (err) {
      log.error("Failed to get safety systems", { error: String(err) });
      res.status(500).json({ message: "Failed to get safety systems" });
    }
  });

  log.info("OT/ICS Security routes registered");
}
