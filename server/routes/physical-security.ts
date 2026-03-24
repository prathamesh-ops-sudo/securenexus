import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count, ilike, or, gte, lte } from "drizzle-orm";
import {
  physicalAssets,
  badgeEvents,
  physicalIncidents,
  visitors,
  physicalSecurityConfig,
  BADGE_EVENT_TYPES,
  PHYSICAL_ASSET_TYPES,
  PHYSICAL_INCIDENT_STATUSES,
  VISITOR_STATUSES,
} from "../../shared/schema";
import {
  runCorrelationAnalysis,
  createPhysicalIncidentsFromCorrelations,
  BUILT_IN_RULES,
} from "../physical-correlation";
import { testControllerConnection } from "../integrations/lenel";
import type { ControllerConfig } from "../integrations/lenel";

const log = logger.child("physical-security");

const ALLOWED_ASSET_FIELDS = [
  "name",
  "assetType",
  "location",
  "building",
  "floor",
  "zone",
  "controllerType",
  "controllerId",
  "ipAddress",
  "isOnline",
  "metadata",
];
const ALLOWED_INCIDENT_FIELDS = [
  "title",
  "description",
  "incidentType",
  "severity",
  "status",
  "location",
  "assignedTo",
  "resolutionNotes",
];
const ALLOWED_VISITOR_FIELDS = [
  "name",
  "email",
  "company",
  "hostEmployeeName",
  "hostEmployeeEmail",
  "purpose",
  "status",
  "badgeNumber",
  "scheduledAt",
  "areasAuthorized",
];
const ALLOWED_CONFIG_FIELDS = [
  "isEnabled",
  "controllerIntegrations",
  "afterHoursStart",
  "afterHoursEnd",
  "tailgateDetectionEnabled",
  "anomalyCorrelationEnabled",
  "autoCreateDigitalIncidents",
];

export function registerPhysicalSecurityRoutes(app: Express): void {
  // ==========================================================================
  // Physical Assets CRUD
  // ==========================================================================

  // GET /api/physical-security/assets
  app.get(
    "/api/physical-security/assets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { type, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(physicalAssets.orgId, orgId)];
        if (type && typeof type === "string") {
          conditions.push(eq(physicalAssets.assetType, type));
        }
        if (search && typeof search === "string") {
          conditions.push(
            or(ilike(physicalAssets.name, `%${search}%`), ilike(physicalAssets.location, `%${search}%`))!,
          );
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(physicalAssets)
            .where(and(...conditions))
            .orderBy(desc(physicalAssets.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(physicalAssets)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list physical assets", { error: String(err) });
        res.status(500).json({ error: "Failed to list physical assets" });
      }
    },
  );

  // POST /api/physical-security/assets
  app.post(
    "/api/physical-security/assets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_ASSET_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name || !body.assetType || !body.location) {
          return res.status(400).json({ error: "name, assetType, and location are required" });
        }

        const [created] = await db
          .insert(physicalAssets)
          .values({ ...body, orgId } as typeof physicalAssets.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create physical asset", { error: String(err) });
        res.status(500).json({ error: "Failed to create physical asset" });
      }
    },
  );

  // GET /api/physical-security/assets/:id
  app.get(
    "/api/physical-security/assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [asset] = await db
          .select()
          .from(physicalAssets)
          .where(and(eq(physicalAssets.id, String(req.params.id)), eq(physicalAssets.orgId, orgId)));
        if (!asset) return res.status(404).json({ error: "Asset not found" });
        res.json(asset);
      } catch (err) {
        log.error("Failed to get physical asset", { error: String(err) });
        res.status(500).json({ error: "Failed to get physical asset" });
      }
    },
  );

  // PATCH /api/physical-security/assets/:id
  app.patch(
    "/api/physical-security/assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_ASSET_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [updated] = await db
          .update(physicalAssets)
          .set(updates)
          .where(and(eq(physicalAssets.id, String(req.params.id)), eq(physicalAssets.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Asset not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update physical asset", { error: String(err) });
        res.status(500).json({ error: "Failed to update physical asset" });
      }
    },
  );

  // DELETE /api/physical-security/assets/:id
  app.delete(
    "/api/physical-security/assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(physicalAssets)
          .where(and(eq(physicalAssets.id, String(req.params.id)), eq(physicalAssets.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Asset not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete physical asset", { error: String(err) });
        res.status(500).json({ error: "Failed to delete physical asset" });
      }
    },
  );

  // ==========================================================================
  // Badge Events
  // ==========================================================================

  // GET /api/physical-security/badge-events
  app.get(
    "/api/physical-security/badge-events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { type, anomaly, search, limit: limitStr, offset: offsetStr, since, until } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(badgeEvents.orgId, orgId)];
        if (type && typeof type === "string") {
          conditions.push(eq(badgeEvents.eventType, type));
        }
        if (anomaly === "true") {
          conditions.push(eq(badgeEvents.isAnomaly, true));
        }
        if (search && typeof search === "string") {
          conditions.push(
            or(
              ilike(badgeEvents.employeeName, `%${search}%`),
              ilike(badgeEvents.badgeNumber, `%${search}%`),
              ilike(badgeEvents.location, `%${search}%`),
            )!,
          );
        }
        if (since && typeof since === "string") {
          conditions.push(gte(badgeEvents.occurredAt, new Date(since)));
        }
        if (until && typeof until === "string") {
          conditions.push(lte(badgeEvents.occurredAt, new Date(until)));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(badgeEvents)
            .where(and(...conditions))
            .orderBy(desc(badgeEvents.occurredAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(badgeEvents)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list badge events", { error: String(err) });
        res.status(500).json({ error: "Failed to list badge events" });
      }
    },
  );

  // POST /api/physical-security/badge-events (ingest from controller webhook)
  app.post(
    "/api/physical-security/badge-events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const {
          eventType,
          badgeNumber,
          employeeName,
          employeeEmail,
          employeeDepartment,
          location,
          doorName,
          direction,
          rawPayload,
        } = req.body;

        if (!eventType || !location) {
          return res.status(400).json({ error: "eventType and location are required" });
        }

        // 67.2 — Enhanced access anomaly detection
        const anomalyTypes = [
          "door_forced",
          "tailgate_detected",
          "antipassback_violation",
          "duress_alarm",
          "card_unknown",
        ];
        let isAnomaly = anomalyTypes.includes(eventType);
        let anomalyReason = isAnomaly ? `Anomalous event type: ${eventType}` : null;

        // 67.2 — Detect after-hours access
        const eventHour = new Date().getUTCHours();
        if (!isAnomaly && (eventHour < 6 || eventHour >= 22)) {
          isAnomaly = true;
          anomalyReason = `After-hours access detected at ${eventHour}:00 UTC`;
        }

        // 67.2 — Detect simultaneous badge use (cloned badge detection)
        if (badgeNumber && !isAnomaly) {
          const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
          const recentBadgeUses = await db
            .select()
            .from(badgeEvents)
            .where(
              and(
                eq(badgeEvents.orgId, orgId),
                eq(badgeEvents.badgeNumber, badgeNumber),
                gte(badgeEvents.occurredAt, fiveMinAgo),
              ),
            )
            .limit(1);
          if (recentBadgeUses.length > 0 && recentBadgeUses[0].location !== location) {
            isAnomaly = true;
            anomalyReason = `Simultaneous badge use: badge ${badgeNumber} used at ${recentBadgeUses[0].location} and ${location} within 5 minutes (possible clone)`;
          }
        }

        const [created] = await db
          .insert(badgeEvents)
          .values({
            orgId,
            eventType,
            badgeNumber: badgeNumber || null,
            employeeName: employeeName || null,
            employeeEmail: employeeEmail || null,
            employeeDepartment: employeeDepartment || null,
            location,
            doorName: doorName || null,
            direction: direction || null,
            isAnomaly,
            anomalyReason,
            rawPayload: rawPayload || {},
          })
          .returning();

        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to ingest badge event", { error: String(err) });
        res.status(500).json({ error: "Failed to ingest badge event" });
      }
    },
  );

  // ==========================================================================
  // Physical Incidents
  // ==========================================================================

  // GET /api/physical-security/incidents
  app.get(
    "/api/physical-security/incidents",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, severity, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(physicalIncidents.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(physicalIncidents.status, status));
        }
        if (severity && typeof severity === "string") {
          conditions.push(eq(physicalIncidents.severity, severity));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(physicalIncidents)
            .where(and(...conditions))
            .orderBy(desc(physicalIncidents.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(physicalIncidents)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list physical incidents", { error: String(err) });
        res.status(500).json({ error: "Failed to list physical incidents" });
      }
    },
  );

  // POST /api/physical-security/incidents
  app.post(
    "/api/physical-security/incidents",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_INCIDENT_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.title || !body.incidentType) {
          return res.status(400).json({ error: "title and incidentType are required" });
        }

        const [created] = await db
          .insert(physicalIncidents)
          .values({ ...body, orgId } as typeof physicalIncidents.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create physical incident", { error: String(err) });
        res.status(500).json({ error: "Failed to create physical incident" });
      }
    },
  );

  // PATCH /api/physical-security/incidents/:id
  app.patch(
    "/api/physical-security/incidents/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_INCIDENT_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }
        if (updates.status === "resolved") {
          updates.resolvedAt = new Date();
        }

        const [updated] = await db
          .update(physicalIncidents)
          .set(updates)
          .where(and(eq(physicalIncidents.id, String(req.params.id)), eq(physicalIncidents.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Incident not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update physical incident", { error: String(err) });
        res.status(500).json({ error: "Failed to update physical incident" });
      }
    },
  );

  // ==========================================================================
  // Visitors
  // ==========================================================================

  // GET /api/physical-security/visitors
  app.get(
    "/api/physical-security/visitors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(visitors.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(visitors.status, status));
        }
        if (search && typeof search === "string") {
          conditions.push(or(ilike(visitors.name, `%${search}%`), ilike(visitors.company, `%${search}%`))!);
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(visitors)
            .where(and(...conditions))
            .orderBy(desc(visitors.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(visitors)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list visitors", { error: String(err) });
        res.status(500).json({ error: "Failed to list visitors" });
      }
    },
  );

  // POST /api/physical-security/visitors
  app.post(
    "/api/physical-security/visitors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_VISITOR_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name) {
          return res.status(400).json({ error: "name is required" });
        }

        const [created] = await db
          .insert(visitors)
          .values({ ...body, orgId } as typeof visitors.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create visitor", { error: String(err) });
        res.status(500).json({ error: "Failed to create visitor" });
      }
    },
  );

  // PATCH /api/physical-security/visitors/:id
  app.patch(
    "/api/physical-security/visitors/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = {};
        for (const key of ALLOWED_VISITOR_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }
        if (updates.status === "checked_in") {
          updates.checkedInAt = new Date();
        }
        if (updates.status === "checked_out") {
          updates.checkedOutAt = new Date();
        }

        const [updated] = await db
          .update(visitors)
          .set(updates)
          .where(and(eq(visitors.id, String(req.params.id)), eq(visitors.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Visitor not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update visitor", { error: String(err) });
        res.status(500).json({ error: "Failed to update visitor" });
      }
    },
  );

  // ==========================================================================
  // Correlation Engine
  // ==========================================================================

  // GET /api/physical-security/correlation/rules
  app.get(
    "/api/physical-security/correlation/rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (_req: Request, res: Response) => {
      res.json({ rules: BUILT_IN_RULES });
    },
  );

  // POST /api/physical-security/correlation/run
  app.post(
    "/api/physical-security/correlation/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const lookbackMinutes = Number(req.body.lookbackMinutes) || 60;
        const results = await runCorrelationAnalysis(orgId, lookbackMinutes);

        // Auto-create incidents if configured
        let incidentsCreated = 0;
        if (req.body.autoCreateIncidents !== false) {
          incidentsCreated = await createPhysicalIncidentsFromCorrelations(orgId, results);
        }

        res.json({ correlations: results, incidentsCreated });
      } catch (err) {
        log.error("Failed to run correlation", { error: String(err) });
        res.status(500).json({ error: "Failed to run correlation analysis" });
      }
    },
  );

  // ==========================================================================
  // Controller Integration
  // ==========================================================================

  // POST /api/physical-security/controllers/test
  app.post(
    "/api/physical-security/controllers/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "admin"),
    async (req: Request, res: Response) => {
      try {
        const config = req.body as ControllerConfig;
        const result = await testControllerConnection(config);
        res.json(result);
      } catch (err) {
        log.error("Failed to test controller", { error: String(err) });
        res.status(500).json({ error: "Failed to test controller connection" });
      }
    },
  );

  // ==========================================================================
  // Configuration
  // ==========================================================================

  // GET /api/physical-security/config
  app.get(
    "/api/physical-security/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(physicalSecurityConfig)
          .where(eq(physicalSecurityConfig.orgId, orgId));
        res.json(
          existing || {
            isEnabled: false,
            controllerIntegrations: [],
            tailgateDetectionEnabled: true,
            anomalyCorrelationEnabled: true,
            autoCreateDigitalIncidents: true,
          },
        );
      } catch (err) {
        log.error("Failed to get config", { error: String(err) });
        res.status(500).json({ error: "Failed to get configuration" });
      }
    },
  );

  // PUT /api/physical-security/config
  app.put(
    "/api/physical-security/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("physical_security", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_CONFIG_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [existing] = await db
          .select()
          .from(physicalSecurityConfig)
          .where(eq(physicalSecurityConfig.orgId, orgId));
        if (existing) {
          const [updated] = await db
            .update(physicalSecurityConfig)
            .set(updates)
            .where(eq(physicalSecurityConfig.id, existing.id))
            .returning();
          res.json(updated);
        } else {
          const [created] = await db
            .insert(physicalSecurityConfig)
            .values({ ...updates, orgId } as typeof physicalSecurityConfig.$inferInsert)
            .returning();
          res.status(201).json(created);
        }
      } catch (err) {
        log.error("Failed to update config", { error: String(err) });
        res.status(500).json({ error: "Failed to update configuration" });
      }
    },
  );

  // ==========================================================================
  // Dashboard / Stats
  // ==========================================================================

  // GET /api/physical-security/dashboard
  app.get(
    "/api/physical-security/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

        const [
          [{ value: totalAssets }],
          [{ value: totalEvents24h }],
          [{ value: anomalyCount }],
          [{ value: openIncidents }],
          [{ value: activeVisitors }],
          recentEvents,
        ] = await Promise.all([
          db.select({ value: count() }).from(physicalAssets).where(eq(physicalAssets.orgId, orgId)),
          db
            .select({ value: count() })
            .from(badgeEvents)
            .where(and(eq(badgeEvents.orgId, orgId), gte(badgeEvents.occurredAt, last24h))),
          db
            .select({ value: count() })
            .from(badgeEvents)
            .where(
              and(eq(badgeEvents.orgId, orgId), eq(badgeEvents.isAnomaly, true), gte(badgeEvents.occurredAt, last24h)),
            ),
          db
            .select({ value: count() })
            .from(physicalIncidents)
            .where(and(eq(physicalIncidents.orgId, orgId), eq(physicalIncidents.status, "open"))),
          db
            .select({ value: count() })
            .from(visitors)
            .where(and(eq(visitors.orgId, orgId), eq(visitors.status, "checked_in"))),
          db
            .select()
            .from(badgeEvents)
            .where(and(eq(badgeEvents.orgId, orgId), gte(badgeEvents.occurredAt, last24h)))
            .orderBy(desc(badgeEvents.occurredAt))
            .limit(10),
        ]);

        // 67.1 — Facility floor plan status summary (assets by zone/status)
        const assetsByZone = await db
          .select({
            zone: physicalAssets.zone,
            assetType: physicalAssets.assetType,
            online: sql<number>`count(*) filter (where ${physicalAssets.isOnline} = true)`,
            offline: sql<number>`count(*) filter (where ${physicalAssets.isOnline} = false)`,
            total: count(),
          })
          .from(physicalAssets)
          .where(eq(physicalAssets.orgId, orgId))
          .groupBy(physicalAssets.zone, physicalAssets.assetType);

        // 67.4 — Physical-cyber convergence: recent correlated events
        const recentAnomalies = await db
          .select()
          .from(badgeEvents)
          .where(
            and(eq(badgeEvents.orgId, orgId), eq(badgeEvents.isAnomaly, true), gte(badgeEvents.occurredAt, last24h)),
          )
          .orderBy(desc(badgeEvents.occurredAt))
          .limit(5);

        // 67.3 — Visitor check-in/check-out flow stats
        const [{ value: totalVisitors }] = await db
          .select({ value: count() })
          .from(visitors)
          .where(eq(visitors.orgId, orgId));
        const [{ value: preRegistered }] = await db
          .select({ value: count() })
          .from(visitors)
          .where(and(eq(visitors.orgId, orgId), eq(visitors.status, "pre_registered")));

        res.json({
          totalAssets,
          totalEvents24h,
          anomalyCount,
          openIncidents,
          activeVisitors,
          recentEvents,
          assetsByZone,
          recentAnomalies,
          visitorStats: { total: totalVisitors, preRegistered, checkedIn: activeVisitors },
          eventTypes: BADGE_EVENT_TYPES,
          assetTypes: PHYSICAL_ASSET_TYPES,
          incidentStatuses: PHYSICAL_INCIDENT_STATUSES,
          visitorStatuses: VISITOR_STATUSES,
        });
      } catch (err) {
        log.error("Failed to get dashboard", { error: String(err) });
        res.status(500).json({ error: "Failed to get dashboard stats" });
      }
    },
  );
}
