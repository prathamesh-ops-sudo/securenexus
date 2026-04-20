import type { Express } from "express";
import { eq, and, desc, sql, count, ilike, or } from "drizzle-orm";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { db } from "../db";
import {
  threatHunts,
  huntResults,
  huntLibrary,
  huntSchedules,
  huntPlaybooks,
  huntNotebooks,
  huntCache,
  huntCollaborations,
  huntScheduleDrifts,
  communityHuntShares,
  alerts,
  incidents,
  HUNT_QUERY_TYPES,
  HUNT_STATUSES,
} from "@shared/schema";
import crypto from "crypto";
import { compileQuery } from "../sigma-compiler";
import { executeHunt, pivotOnIoc, generateHuntHypotheses } from "../hunt-engine";

const log = logger.child("threat-hunting");

const ALLOWED_QUERY_TYPES = HUNT_QUERY_TYPES as readonly string[];
const ALLOWED_STATUSES = HUNT_STATUSES as readonly string[];
const ALLOWED_CADENCES = ["daily", "weekly", "biweekly", "monthly"];
const ALLOWED_DIFFICULTIES = ["beginner", "intermediate", "advanced"];
const ALLOWED_IOC_TYPES = ["ip", "domain", "hash", "email", "url", "file", "cve"];
const ALLOWED_CATEGORIES = [
  "apt",
  "ransomware",
  "insider_threat",
  "lateral_movement",
  "credential_access",
  "data_exfiltration",
  "persistence",
  "c2",
  "other",
];

export function registerThreatHuntingRoutes(app: Express): void {
  // =========================================================================
  // HUNTS CRUD
  // =========================================================================

  // List hunts
  app.get("/api/threat-hunting/hunts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status ? String(req.query.status) : undefined;
      const queryType = req.query.queryType ? String(req.query.queryType) : undefined;

      const conditions = [eq(threatHunts.orgId, orgId)];
      if (status && ALLOWED_STATUSES.includes(status)) {
        conditions.push(eq(threatHunts.status, status));
      }
      if (queryType && ALLOWED_QUERY_TYPES.includes(queryType)) {
        conditions.push(eq(threatHunts.queryType, queryType));
      }

      const hunts = await db
        .select()
        .from(threatHunts)
        .where(and(...conditions))
        .orderBy(desc(threatHunts.updatedAt))
        .limit(200);

      res.json({ hunts });
    } catch (error) {
      log.error("List hunts error", { error: String(error) });
      res.status(500).json({ message: "Failed to list hunts" });
    }
  });

  // Create hunt
  app.post("/api/threat-hunting/hunts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, description, queryType, queryText, hypothesis, mitreTechniques, tags } = req.body;

      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "Name is required" });
      }
      if (!queryType || !ALLOWED_QUERY_TYPES.includes(queryType)) {
        return res
          .status(400)
          .json({ message: `Invalid query type. Must be one of: ${ALLOWED_QUERY_TYPES.join(", ")}` });
      }
      if (!queryText || typeof queryText !== "string") {
        return res.status(400).json({ message: "Query text is required" });
      }

      // Compile the query to validate it
      let compiledQuery: string | null = null;
      try {
        const compiled = compileQuery(queryType, queryText);
        compiledQuery = JSON.stringify(compiled);
      } catch {
        // Compilation failure is non-fatal — store as draft
      }

      const [hunt] = await db
        .insert(threatHunts)
        .values({
          orgId,
          name: name.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 2000) : null,
          queryType,
          queryText: queryText.substring(0, 10000),
          compiledQuery,
          status: compiledQuery ? "ready" : "draft",
          hypothesis: typeof hypothesis === "string" ? hypothesis.substring(0, 2000) : null,
          mitreTechniques: Array.isArray(mitreTechniques) ? mitreTechniques.slice(0, 20) : [],
          tags: Array.isArray(tags) ? tags.slice(0, 20) : [],
          createdBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      res.status(201).json({ hunt });
    } catch (error) {
      log.error("Create hunt error", { error: String(error) });
      res.status(500).json({ message: "Failed to create hunt" });
    }
  });

  // Get hunt detail
  app.get("/api/threat-hunting/hunts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));

      if (!hunt) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      // Get recent results
      const results = await db
        .select()
        .from(huntResults)
        .where(and(eq(huntResults.huntId, id), eq(huntResults.orgId, orgId)))
        .orderBy(desc(huntResults.executedAt))
        .limit(20);

      // Get schedule if any
      const schedules = await db
        .select()
        .from(huntSchedules)
        .where(and(eq(huntSchedules.huntId, id), eq(huntSchedules.orgId, orgId)));

      // Get library entry if any
      const [libraryEntry] = await db
        .select()
        .from(huntLibrary)
        .where(and(eq(huntLibrary.huntId, id), eq(huntLibrary.orgId, orgId)));

      res.json({ hunt, results, schedules, libraryEntry: libraryEntry || null });
    } catch (error) {
      log.error("Get hunt error", { error: String(error) });
      res.status(500).json({ message: "Failed to get hunt" });
    }
  });

  // Update hunt
  app.put("/api/threat-hunting/hunts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [existing] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));

      if (!existing) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      const { name, description, queryType, queryText, hypothesis, mitreTechniques, tags, status } = req.body;

      const updateData: Record<string, unknown> = { updatedAt: new Date() };
      if (name && typeof name === "string") updateData.name = name.substring(0, 200);
      if (typeof description === "string") updateData.description = description.substring(0, 2000);
      if (queryType && ALLOWED_QUERY_TYPES.includes(queryType)) updateData.queryType = queryType;
      if (queryText && typeof queryText === "string") {
        updateData.queryText = queryText.substring(0, 10000);
        // Re-compile
        try {
          const compiled = compileQuery((updateData.queryType as string) || existing.queryType, queryText);
          updateData.compiledQuery = JSON.stringify(compiled);
        } catch {
          updateData.compiledQuery = null;
        }
      }
      if (typeof hypothesis === "string") updateData.hypothesis = hypothesis.substring(0, 2000);
      if (Array.isArray(mitreTechniques)) updateData.mitreTechniques = mitreTechniques.slice(0, 20);
      if (Array.isArray(tags)) updateData.tags = tags.slice(0, 20);
      if (status && ALLOWED_STATUSES.includes(status)) updateData.status = status;

      const [updated] = await db
        .update(threatHunts)
        .set(updateData)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)))
        .returning();

      res.json({ hunt: updated });
    } catch (error) {
      log.error("Update hunt error", { error: String(error) });
      res.status(500).json({ message: "Failed to update hunt" });
    }
  });

  // Delete hunt
  app.delete("/api/threat-hunting/hunts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [existing] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));

      if (!existing) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      await db.delete(threatHunts).where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));
      res.json({ message: "Hunt deleted" });
    } catch (error) {
      log.error("Delete hunt error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete hunt" });
    }
  });

  // =========================================================================
  // HUNT EXECUTION
  // =========================================================================

  app.post("/api/threat-hunting/hunts/:id/execute", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const limit = Math.min(Math.max(1, Number(req.body.limit) || 100), 500);

      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));

      if (!hunt) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      // Mark as running
      await db.update(threatHunts).set({ status: "running", updatedAt: new Date() }).where(eq(threatHunts.id, id));

      const result = await executeHunt(hunt.queryType, hunt.queryText, orgId, limit);

      // Store result
      const [savedResult] = await db
        .insert(huntResults)
        .values({
          orgId,
          huntId: id,
          eventCount: result.eventCount,
          eventsJson: result.events,
          executionDurationMs: result.executionDurationMs,
          executedBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      // Update hunt status and stats
      await db
        .update(threatHunts)
        .set({
          status: "completed",
          lastRunAt: new Date(),
          lastRunDurationMs: result.executionDurationMs,
          lastRunEventCount: result.eventCount,
          updatedAt: new Date(),
        })
        .where(eq(threatHunts.id, id));

      res.json({ result: savedResult, execution: result });
    } catch (error) {
      log.error("Execute hunt error", { error: String(error) });
      // Reset status on failure
      const id = String(req.params.id);
      await db
        .update(threatHunts)
        .set({ status: "failed", updatedAt: new Date() })
        .where(eq(threatHunts.id, id))
        .catch((err) => log.warn("Failed to update hunt status on error", { error: String(err), huntId: id }));
      res.status(500).json({ message: "Failed to execute hunt" });
    }
  });

  // =========================================================================
  // HUNT RESULTS
  // =========================================================================

  app.get("/api/threat-hunting/results/:huntId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const huntId = String(req.params.huntId);

      // Verify hunt belongs to org
      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, huntId), eq(threatHunts.orgId, orgId)));

      if (!hunt) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      const results = await db
        .select()
        .from(huntResults)
        .where(and(eq(huntResults.huntId, huntId), eq(huntResults.orgId, orgId)))
        .orderBy(desc(huntResults.executedAt))
        .limit(50);

      res.json({ results });
    } catch (error) {
      log.error("Get hunt results error", { error: String(error) });
      res.status(500).json({ message: "Failed to get hunt results" });
    }
  });

  // =========================================================================
  // HUNT SCHEDULES
  // =========================================================================

  app.get("/api/threat-hunting/schedules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const allSchedules = await db
        .select({
          schedule: huntSchedules,
          huntName: threatHunts.name,
          huntQueryType: threatHunts.queryType,
        })
        .from(huntSchedules)
        .leftJoin(threatHunts, eq(huntSchedules.huntId, threatHunts.id))
        .where(eq(huntSchedules.orgId, orgId))
        .orderBy(desc(huntSchedules.createdAt))
        .limit(100);

      res.json({ schedules: allSchedules });
    } catch (error) {
      log.error("List schedules error", { error: String(error) });
      res.status(500).json({ message: "Failed to list schedules" });
    }
  });

  app.post("/api/threat-hunting/schedules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { huntId, cadence, dayOfWeek, hourUtc } = req.body;

      if (!huntId || typeof huntId !== "string") {
        return res.status(400).json({ message: "Hunt ID is required" });
      }
      if (!cadence || !ALLOWED_CADENCES.includes(cadence)) {
        return res.status(400).json({ message: `Invalid cadence. Must be one of: ${ALLOWED_CADENCES.join(", ")}` });
      }

      // Verify hunt belongs to org
      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, huntId), eq(threatHunts.orgId, orgId)));

      if (!hunt) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      const safeHour = Math.max(0, Math.min(23, Number(hourUtc) || 8));
      const safeDow = dayOfWeek !== undefined ? Math.max(0, Math.min(6, Number(dayOfWeek))) : null;

      const [schedule] = await db
        .insert(huntSchedules)
        .values({
          orgId,
          huntId,
          cadence,
          dayOfWeek: safeDow,
          hourUtc: safeHour,
          nextRunAt: computeNextRun(cadence, safeHour, safeDow),
        })
        .returning();

      res.status(201).json({ schedule });
    } catch (error) {
      log.error("Create schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create schedule" });
    }
  });

  app.patch("/api/threat-hunting/schedules/:id/toggle", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [schedule] = await db
        .select()
        .from(huntSchedules)
        .where(and(eq(huntSchedules.id, id), eq(huntSchedules.orgId, orgId)));

      if (!schedule) {
        return res.status(404).json({ message: "Schedule not found" });
      }

      const [updated] = await db
        .update(huntSchedules)
        .set({ enabled: !schedule.enabled })
        .where(and(eq(huntSchedules.id, id), eq(huntSchedules.orgId, orgId)))
        .returning();

      res.json({ schedule: updated });
    } catch (error) {
      log.error("Toggle schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to toggle schedule" });
    }
  });

  app.delete("/api/threat-hunting/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [schedule] = await db
        .select()
        .from(huntSchedules)
        .where(and(eq(huntSchedules.id, id), eq(huntSchedules.orgId, orgId)));

      if (!schedule) {
        return res.status(404).json({ message: "Schedule not found" });
      }

      await db.delete(huntSchedules).where(and(eq(huntSchedules.id, id), eq(huntSchedules.orgId, orgId)));
      res.json({ message: "Schedule deleted" });
    } catch (error) {
      log.error("Delete schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete schedule" });
    }
  });

  // =========================================================================
  // HUNT LIBRARY
  // =========================================================================

  app.get("/api/threat-hunting/library", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const category = req.query.category ? String(req.query.category) : undefined;
      const difficulty = req.query.difficulty ? String(req.query.difficulty) : undefined;

      const conditions = [or(eq(huntLibrary.orgId, orgId), eq(huntLibrary.isPublic, true))];
      if (category && ALLOWED_CATEGORIES.includes(category)) {
        conditions.push(eq(huntLibrary.category, category));
      }
      if (difficulty && ALLOWED_DIFFICULTIES.includes(difficulty)) {
        conditions.push(eq(huntLibrary.difficulty, difficulty));
      }

      const entries = await db
        .select({
          library: huntLibrary,
          huntName: threatHunts.name,
          huntDescription: threatHunts.description,
          huntQueryType: threatHunts.queryType,
          huntQueryText: threatHunts.queryText,
        })
        .from(huntLibrary)
        .leftJoin(threatHunts, eq(huntLibrary.huntId, threatHunts.id))
        .where(and(...conditions))
        .orderBy(desc(huntLibrary.sharedAt))
        .limit(100);

      res.json({ entries });
    } catch (error) {
      log.error("List library error", { error: String(error) });
      res.status(500).json({ message: "Failed to list library" });
    }
  });

  // Share hunt to library
  app.post("/api/threat-hunting/library", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { huntId, isPublic, category, difficulty } = req.body;

      if (!huntId || typeof huntId !== "string") {
        return res.status(400).json({ message: "Hunt ID is required" });
      }

      // Verify hunt belongs to org
      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, huntId), eq(threatHunts.orgId, orgId)));

      if (!hunt) {
        return res.status(404).json({ message: "Hunt not found" });
      }

      const [entry] = await db
        .insert(huntLibrary)
        .values({
          orgId,
          huntId,
          isPublic: isPublic === true,
          sharedBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
          category: category && ALLOWED_CATEGORIES.includes(category) ? category : null,
          difficulty: difficulty && ALLOWED_DIFFICULTIES.includes(difficulty) ? difficulty : null,
        })
        .returning();

      res.status(201).json({ entry });
    } catch (error) {
      log.error("Share to library error", { error: String(error) });
      res.status(500).json({ message: "Failed to share hunt" });
    }
  });

  // =========================================================================
  // PIVOT INTERFACE
  // =========================================================================

  app.post("/api/threat-hunting/pivot/:iocType/:iocValue", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const iocType = String(req.params.iocType);
      const iocValue = String(req.params.iocValue);

      if (!ALLOWED_IOC_TYPES.includes(iocType)) {
        return res.status(400).json({ message: `Invalid IOC type. Must be one of: ${ALLOWED_IOC_TYPES.join(", ")}` });
      }

      if (!iocValue || iocValue.length > 500) {
        return res.status(400).json({ message: "IOC value is required and must be under 500 characters" });
      }

      const result = await pivotOnIoc(iocType, iocValue, orgId);
      res.json(result);
    } catch (error) {
      log.error("Pivot error", { error: String(error) });
      res.status(500).json({ message: "Failed to pivot on IOC" });
    }
  });

  // =========================================================================
  // HYPOTHESIS-DRIVEN HUNTING
  // =========================================================================

  app.get("/api/threat-hunting/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get recent alerts to generate hypotheses
      const recentAlerts = await db
        .select({
          severity: alerts.severity,
          source: alerts.source,
          category: alerts.category,
        })
        .from(alerts)
        .where(eq(alerts.orgId, orgId))
        .orderBy(desc(alerts.createdAt))
        .limit(100);

      const hypotheses = generateHuntHypotheses(recentAlerts);
      res.json({ hypotheses });
    } catch (error) {
      log.error("Generate hypotheses error", { error: String(error) });
      res.status(500).json({ message: "Failed to generate hypotheses" });
    }
  });

  // =========================================================================
  // HUNT PLAYBOOKS
  // =========================================================================

  app.get("/api/threat-hunting/playbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const threatActor = req.query.threatActor ? String(req.query.threatActor) : undefined;

      const conditions = [eq(huntPlaybooks.orgId, orgId)];
      if (threatActor) {
        conditions.push(ilike(huntPlaybooks.threatActor, `%${threatActor}%`));
      }

      const playbooks = await db
        .select()
        .from(huntPlaybooks)
        .where(and(...conditions))
        .orderBy(desc(huntPlaybooks.updatedAt))
        .limit(100);

      res.json({ playbooks });
    } catch (error) {
      log.error("List playbooks error", { error: String(error) });
      res.status(500).json({ message: "Failed to list playbooks" });
    }
  });

  app.post("/api/threat-hunting/playbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const {
        name,
        description,
        threatActor,
        mitreTechniques,
        steps,
        difficulty,
        estimatedTimeMin,
        datasourcesRequired,
      } = req.body;

      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "Name is required" });
      }

      const [playbook] = await db
        .insert(huntPlaybooks)
        .values({
          orgId,
          name: name.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 2000) : null,
          threatActor: typeof threatActor === "string" ? threatActor.substring(0, 100) : null,
          mitreTechniques: Array.isArray(mitreTechniques) ? mitreTechniques.slice(0, 20) : [],
          steps: Array.isArray(steps) ? steps.slice(0, 50) : [],
          difficulty: difficulty && ALLOWED_DIFFICULTIES.includes(difficulty) ? difficulty : "intermediate",
          estimatedTimeMin: typeof estimatedTimeMin === "number" ? Math.max(1, Math.min(480, estimatedTimeMin)) : null,
          datasourcesRequired: Array.isArray(datasourcesRequired) ? datasourcesRequired.slice(0, 20) : [],
          createdBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      res.status(201).json({ playbook });
    } catch (error) {
      log.error("Create playbook error", { error: String(error) });
      res.status(500).json({ message: "Failed to create playbook" });
    }
  });

  app.get("/api/threat-hunting/playbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [playbook] = await db
        .select()
        .from(huntPlaybooks)
        .where(and(eq(huntPlaybooks.id, id), eq(huntPlaybooks.orgId, orgId)));

      if (!playbook) {
        return res.status(404).json({ message: "Playbook not found" });
      }

      res.json({ playbook });
    } catch (error) {
      log.error("Get playbook error", { error: String(error) });
      res.status(500).json({ message: "Failed to get playbook" });
    }
  });

  app.delete("/api/threat-hunting/playbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [playbook] = await db
        .select()
        .from(huntPlaybooks)
        .where(and(eq(huntPlaybooks.id, id), eq(huntPlaybooks.orgId, orgId)));

      if (!playbook) {
        return res.status(404).json({ message: "Playbook not found" });
      }

      await db.delete(huntPlaybooks).where(and(eq(huntPlaybooks.id, id), eq(huntPlaybooks.orgId, orgId)));
      res.json({ message: "Playbook deleted" });
    } catch (error) {
      log.error("Delete playbook error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete playbook" });
    }
  });

  // =========================================================================
  // STATS / OVERVIEW
  // =========================================================================

  app.get("/api/threat-hunting/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [huntCount] = await db.select({ count: count() }).from(threatHunts).where(eq(threatHunts.orgId, orgId));

      const [resultCount] = await db.select({ count: count() }).from(huntResults).where(eq(huntResults.orgId, orgId));

      const [scheduleCount] = await db
        .select({ count: count() })
        .from(huntSchedules)
        .where(and(eq(huntSchedules.orgId, orgId), eq(huntSchedules.enabled, true)));

      const [playbookCount] = await db
        .select({ count: count() })
        .from(huntPlaybooks)
        .where(eq(huntPlaybooks.orgId, orgId));

      const recentResults = await db
        .select({
          eventCount: huntResults.eventCount,
          executedAt: huntResults.executedAt,
          executionDurationMs: huntResults.executionDurationMs,
        })
        .from(huntResults)
        .where(eq(huntResults.orgId, orgId))
        .orderBy(desc(huntResults.executedAt))
        .limit(30);

      res.json({
        totalHunts: huntCount?.count || 0,
        totalExecutions: resultCount?.count || 0,
        activeSchedules: scheduleCount?.count || 0,
        totalPlaybooks: playbookCount?.count || 0,
        recentResults,
      });
    } catch (error) {
      log.error("Get stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to get stats" });
    }
  });

  // =========================================================================
  // MITRE ATT&CK COVERAGE
  // =========================================================================

  app.get("/api/threat-hunting/mitre-coverage", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get all hunts with their MITRE techniques
      const hunts = await db
        .select({
          id: threatHunts.id,
          name: threatHunts.name,
          mitreTechniques: threatHunts.mitreTechniques,
          status: threatHunts.status,
          lastRunAt: threatHunts.lastRunAt,
        })
        .from(threatHunts)
        .where(eq(threatHunts.orgId, orgId));

      // Build coverage map
      const coverageMap: Record<string, { huntCount: number; huntNames: string[]; lastRun: string | null }> = {};

      for (const hunt of hunts) {
        const techniques = Array.isArray(hunt.mitreTechniques) ? (hunt.mitreTechniques as string[]) : [];
        for (const tech of techniques) {
          if (!coverageMap[tech]) {
            coverageMap[tech] = { huntCount: 0, huntNames: [], lastRun: null };
          }
          coverageMap[tech].huntCount++;
          coverageMap[tech].huntNames.push(hunt.name);
          if (hunt.lastRunAt) {
            const runStr = hunt.lastRunAt.toISOString();
            if (!coverageMap[tech].lastRun || runStr > coverageMap[tech].lastRun) {
              coverageMap[tech].lastRun = runStr;
            }
          }
        }
      }

      res.json({ coverage: coverageMap, totalHunts: hunts.length });
    } catch (error) {
      log.error("Get MITRE coverage error", { error: String(error) });
      res.status(500).json({ message: "Failed to get MITRE coverage" });
    }
  });

  // =========================================================================
  // HUNT RESULT → INCIDENT INTEGRATION
  // =========================================================================

  // Create a new incident from a hunt result
  app.post("/api/threat-hunting/results/:id/create-incident", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const resultId = String(req.params.id);

      const [result] = await db
        .select()
        .from(huntResults)
        .where(and(eq(huntResults.id, resultId), eq(huntResults.orgId, orgId)));

      if (!result) {
        return res.status(404).json({ message: "Hunt result not found" });
      }

      // Get the parent hunt for context
      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, result.huntId), eq(threatHunts.orgId, orgId)));

      const huntName = hunt?.name || "Unknown Hunt";

      const [incident] = await db
        .insert(incidents)
        .values({
          orgId,
          title: `Threat Hunt Finding: ${huntName}`,
          summary: `Incident created from threat hunt "${huntName}" result with ${result.eventCount} matched events. Executed at ${result.executedAt?.toISOString() || "unknown time"}.`,
          severity: result.eventCount >= 10 ? "critical" : result.eventCount >= 5 ? "high" : "medium",
          status: "open",
          mitreTechniques: hunt?.mitreTechniques as string[] | undefined,
          affectedAssets: result.eventsJson
            ? { huntResultEvents: (result.eventsJson as unknown[]).slice(0, 20) }
            : undefined,
        })
        .returning();

      // Update the hunt result to reference the new incident
      await db.update(huntResults).set({ linkedIncidentId: incident.id }).where(eq(huntResults.id, resultId));

      res.json({ incident, message: "Incident created and linked to hunt result" });
    } catch (error) {
      log.error("Create incident from hunt result error", { error: String(error) });
      res.status(500).json({ message: "Failed to create incident" });
    }
  });

  // Link a hunt result to an existing incident
  app.patch("/api/threat-hunting/results/:id/link-incident", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const resultId = String(req.params.id);
      const { incidentId } = req.body;

      if (!incidentId || typeof incidentId !== "string") {
        return res.status(400).json({ message: "incidentId is required" });
      }

      const [result] = await db
        .select()
        .from(huntResults)
        .where(and(eq(huntResults.id, resultId), eq(huntResults.orgId, orgId)));

      if (!result) {
        return res.status(404).json({ message: "Hunt result not found" });
      }

      // Verify the incident belongs to the same org
      const [incident] = await db
        .select()
        .from(incidents)
        .where(and(eq(incidents.id, incidentId), eq(incidents.orgId, orgId)));

      if (!incident) {
        return res.status(404).json({ message: "Incident not found" });
      }

      await db.update(huntResults).set({ linkedIncidentId: incidentId }).where(eq(huntResults.id, resultId));

      res.json({ message: "Hunt result linked to incident", incidentId });
    } catch (error) {
      log.error("Link hunt result to incident error", { error: String(error) });
      res.status(500).json({ message: "Failed to link to incident" });
    }
  });

  // =========================================================================
  // HUNT NOTEBOOKS (multi-step chained investigations)
  // =========================================================================

  app.get("/api/threat-hunting/notebooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const notebooks = await db
        .select()
        .from(huntNotebooks)
        .where(eq(huntNotebooks.orgId, orgId))
        .orderBy(desc(huntNotebooks.updatedAt))
        .limit(50);
      res.json({ notebooks });
    } catch (error) {
      log.error("List notebooks error", { error: String(error) });
      res.status(500).json({ message: "Failed to list notebooks" });
    }
  });

  app.post("/api/threat-hunting/notebooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, description, steps } = req.body;
      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "Name is required" });
      }
      const [notebook] = await db
        .insert(huntNotebooks)
        .values({
          orgId,
          name: name.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 2000) : null,
          steps: Array.isArray(steps) ? steps.slice(0, 50) : [],
          createdBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();
      res.status(201).json({ notebook });
    } catch (error) {
      log.error("Create notebook error", { error: String(error) });
      res.status(500).json({ message: "Failed to create notebook" });
    }
  });

  app.put("/api/threat-hunting/notebooks/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const [existing] = await db
        .select()
        .from(huntNotebooks)
        .where(and(eq(huntNotebooks.id, id), eq(huntNotebooks.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "Notebook not found" });

      const { name, description, steps } = req.body;
      const updateData: Record<string, unknown> = { updatedAt: new Date() };
      if (name && typeof name === "string") updateData.name = name.substring(0, 200);
      if (typeof description === "string") updateData.description = description.substring(0, 2000);
      if (Array.isArray(steps)) updateData.steps = steps.slice(0, 50);

      const [updated] = await db
        .update(huntNotebooks)
        .set(updateData)
        .where(and(eq(huntNotebooks.id, id), eq(huntNotebooks.orgId, orgId)))
        .returning();
      res.json({ notebook: updated });
    } catch (error) {
      log.error("Update notebook error", { error: String(error) });
      res.status(500).json({ message: "Failed to update notebook" });
    }
  });

  app.delete("/api/threat-hunting/notebooks/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const [existing] = await db
        .select()
        .from(huntNotebooks)
        .where(and(eq(huntNotebooks.id, id), eq(huntNotebooks.orgId, orgId)));
      if (!existing) return res.status(404).json({ message: "Notebook not found" });
      await db.delete(huntNotebooks).where(and(eq(huntNotebooks.id, id), eq(huntNotebooks.orgId, orgId)));
      res.json({ message: "Notebook deleted" });
    } catch (error) {
      log.error("Delete notebook error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete notebook" });
    }
  });

  // Execute a single notebook step
  app.post("/api/threat-hunting/notebooks/:id/execute-step", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { stepIndex, queryType, queryText } = req.body;

      const [notebook] = await db
        .select()
        .from(huntNotebooks)
        .where(and(eq(huntNotebooks.id, id), eq(huntNotebooks.orgId, orgId)));
      if (!notebook) return res.status(404).json({ message: "Notebook not found" });

      if (!queryType || !ALLOWED_QUERY_TYPES.includes(queryType)) {
        return res.status(400).json({ message: "Invalid query type" });
      }
      if (!queryText || typeof queryText !== "string") {
        return res.status(400).json({ message: "Query text is required" });
      }

      const result = await executeHunt(queryType, queryText, orgId, 100);

      // Update the step with results
      const steps = Array.isArray(notebook.steps) ? [...(notebook.steps as Record<string, unknown>[])] : [];
      const idx = typeof stepIndex === "number" ? stepIndex : steps.length - 1;
      if (idx >= 0 && idx < steps.length) {
        steps[idx] = {
          ...steps[idx],
          resultSummary: `${result.eventCount} events found in ${result.executionDurationMs}ms`,
          lastExecutedAt: new Date().toISOString(),
          eventCount: result.eventCount,
        };
      }

      await db.update(huntNotebooks).set({ steps, updatedAt: new Date() }).where(eq(huntNotebooks.id, id));

      res.json({ result, stepIndex: idx });
    } catch (error) {
      log.error("Execute notebook step error", { error: String(error) });
      res.status(500).json({ message: "Failed to execute step" });
    }
  });

  // =========================================================================
  // COLLABORATIVE HUNTING SESSIONS
  // =========================================================================

  app.get("/api/threat-hunting/collaborations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sessions = await db
        .select()
        .from(huntCollaborations)
        .where(eq(huntCollaborations.orgId, orgId))
        .orderBy(desc(huntCollaborations.startedAt))
        .limit(50);
      res.json({ sessions });
    } catch (error) {
      log.error("List collaborations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list collaboration sessions" });
    }
  });

  app.post("/api/threat-hunting/collaborations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { huntId, sessionName } = req.body;
      if (!sessionName || typeof sessionName !== "string") {
        return res.status(400).json({ message: "Session name is required" });
      }

      // Verify hunt belongs to org if huntId provided
      if (huntId) {
        const [hunt] = await db
          .select()
          .from(threatHunts)
          .where(and(eq(threatHunts.id, huntId), eq(threatHunts.orgId, orgId)));
        if (!hunt) return res.status(404).json({ message: "Hunt not found" });
      }

      const userId = ((req as unknown as Record<string, unknown>).userId as string) || "unknown";
      const [session] = await db
        .insert(huntCollaborations)
        .values({
          orgId,
          huntId: huntId || null,
          sessionName: sessionName.substring(0, 200),
          participants: [{ userId, name: userId, color: "#3b82f6", joinedAt: new Date().toISOString() }],
          status: "active",
        })
        .returning();
      res.status(201).json({ session });
    } catch (error) {
      log.error("Create collaboration error", { error: String(error) });
      res.status(500).json({ message: "Failed to create collaboration session" });
    }
  });

  app.post("/api/threat-hunting/collaborations/:id/join", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const [session] = await db
        .select()
        .from(huntCollaborations)
        .where(and(eq(huntCollaborations.id, id), eq(huntCollaborations.orgId, orgId)));
      if (!session) return res.status(404).json({ message: "Session not found" });

      const userId = ((req as unknown as Record<string, unknown>).userId as string) || "unknown";
      const participants = Array.isArray(session.participants)
        ? [...(session.participants as Record<string, unknown>[])]
        : [];
      const colors = ["#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#8b5cf6", "#ec4899"];
      participants.push({
        userId,
        name: userId,
        color: colors[participants.length % colors.length],
        joinedAt: new Date().toISOString(),
      });

      const [updated] = await db
        .update(huntCollaborations)
        .set({ participants })
        .where(eq(huntCollaborations.id, id))
        .returning();
      res.json({ session: updated });
    } catch (error) {
      log.error("Join collaboration error", { error: String(error) });
      res.status(500).json({ message: "Failed to join session" });
    }
  });

  app.post("/api/threat-hunting/collaborations/:id/message", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { message } = req.body;
      if (!message || typeof message !== "string") {
        return res.status(400).json({ message: "Message is required" });
      }

      const [session] = await db
        .select()
        .from(huntCollaborations)
        .where(and(eq(huntCollaborations.id, id), eq(huntCollaborations.orgId, orgId)));
      if (!session) return res.status(404).json({ message: "Session not found" });

      const userId = ((req as unknown as Record<string, unknown>).userId as string) || "unknown";
      const chatMessages = Array.isArray(session.chatMessages)
        ? [...(session.chatMessages as Record<string, unknown>[])]
        : [];
      chatMessages.push({
        userId,
        name: userId,
        message: message.substring(0, 2000),
        timestamp: new Date().toISOString(),
      });

      const [updated] = await db
        .update(huntCollaborations)
        .set({ chatMessages })
        .where(eq(huntCollaborations.id, id))
        .returning();
      res.json({ session: updated });
    } catch (error) {
      log.error("Send collaboration message error", { error: String(error) });
      res.status(500).json({ message: "Failed to send message" });
    }
  });

  app.post("/api/threat-hunting/collaborations/:id/end", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const [session] = await db
        .select()
        .from(huntCollaborations)
        .where(and(eq(huntCollaborations.id, id), eq(huntCollaborations.orgId, orgId)));
      if (!session) return res.status(404).json({ message: "Session not found" });

      const [updated] = await db
        .update(huntCollaborations)
        .set({ status: "ended", endedAt: new Date() })
        .where(eq(huntCollaborations.id, id))
        .returning();
      res.json({ session: updated });
    } catch (error) {
      log.error("End collaboration error", { error: String(error) });
      res.status(500).json({ message: "Failed to end session" });
    }
  });

  // =========================================================================
  // QUERY EXECUTION PLAN / OPTIMIZATION
  // =========================================================================

  app.post("/api/threat-hunting/hunts/:id/execution-plan", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));
      if (!hunt) return res.status(404).json({ message: "Hunt not found" });

      // Generate execution plan based on query type and content
      const dataSources: string[] = [];
      const queryLower = hunt.queryText.toLowerCase();

      if (queryLower.includes("alert") || queryLower.includes("severity")) dataSources.push("alerts");
      if (queryLower.includes("log") || queryLower.includes("ingestion")) dataSources.push("ingestion_logs");
      if (queryLower.includes("asset") || queryLower.includes("host")) dataSources.push("assets");
      if (queryLower.includes("network") || queryLower.includes("flow")) dataSources.push("network_flows");
      if (queryLower.includes("process") || queryLower.includes("cmd")) dataSources.push("process_events");
      if (queryLower.includes("file") || queryLower.includes("registry")) dataSources.push("file_events");
      if (dataSources.length === 0) dataSources.push("alerts", "ingestion_logs");

      // Estimate result set size based on data sources
      const estimatedRows = dataSources.length * 500;
      const estimatedTimeMs = dataSources.length * 500 + estimatedRows * 0.1;

      const plan = {
        queryType: hunt.queryType,
        dataSources,
        estimatedRows,
        estimatedTimeMs: Math.round(estimatedTimeMs),
        optimizations: [] as string[],
        warnings: [] as string[],
        steps: [
          { phase: "parse", description: `Parse ${hunt.queryType.toUpperCase()} query`, estimatedMs: 10 },
          { phase: "compile", description: "Compile to internal representation", estimatedMs: 25 },
          { phase: "plan", description: `Scan ${dataSources.length} data source(s)`, estimatedMs: 50 },
          {
            phase: "execute",
            description: `Execute across ${dataSources.join(", ")}`,
            estimatedMs: Math.round(estimatedTimeMs * 0.7),
          },
          {
            phase: "aggregate",
            description: "Aggregate and deduplicate results",
            estimatedMs: Math.round(estimatedTimeMs * 0.2),
          },
        ],
      };

      // Add optimizations
      if (hunt.compiledQuery) plan.optimizations.push("Query pre-compiled and cached");
      if (dataSources.length === 1) plan.optimizations.push("Single data source — no join overhead");
      if (queryLower.includes("limit")) plan.optimizations.push("Result limit detected — early termination enabled");
      if (queryLower.includes("where") || queryLower.includes("filter"))
        plan.optimizations.push("Filter pushdown applied");

      // Add warnings
      if (dataSources.length > 3) plan.warnings.push("Multiple data sources may increase execution time");
      if (hunt.queryText.length > 2000)
        plan.warnings.push("Complex query — consider breaking into smaller sub-queries");
      if (!hunt.compiledQuery) plan.warnings.push("Query not pre-compiled — first execution may be slower");

      res.json({ plan });
    } catch (error) {
      log.error("Execution plan error", { error: String(error) });
      res.status(500).json({ message: "Failed to generate execution plan" });
    }
  });

  // =========================================================================
  // HUNT RESULT CACHING
  // =========================================================================

  app.get("/api/threat-hunting/cache", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const entries = await db
        .select()
        .from(huntCache)
        .where(eq(huntCache.orgId, orgId))
        .orderBy(desc(huntCache.cachedAt))
        .limit(50);

      // Mark expired entries
      const now = new Date();
      const enriched = entries.map((e) => ({
        ...e,
        isExpired: new Date(e.expiresAt) < now,
      }));

      res.json({ entries: enriched });
    } catch (error) {
      log.error("List cache error", { error: String(error) });
      res.status(500).json({ message: "Failed to list cache entries" });
    }
  });

  app.post("/api/threat-hunting/cache/lookup", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { queryHash } = req.body;
      if (!queryHash || typeof queryHash !== "string") {
        return res.status(400).json({ message: "queryHash is required" });
      }

      const [entry] = await db
        .select()
        .from(huntCache)
        .where(and(eq(huntCache.orgId, orgId), eq(huntCache.queryHash, queryHash)));

      if (!entry) {
        return res.json({ hit: false, entry: null });
      }

      const now = new Date();
      if (new Date(entry.expiresAt) < now) {
        return res.json({ hit: false, entry: null, reason: "expired" });
      }

      // Increment hit count
      await db
        .update(huntCache)
        .set({ hitCount: sql`${huntCache.hitCount} + 1` })
        .where(eq(huntCache.id, entry.id));

      res.json({ hit: true, entry });
    } catch (error) {
      log.error("Cache lookup error", { error: String(error) });
      res.status(500).json({ message: "Failed to lookup cache" });
    }
  });

  app.delete("/api/threat-hunting/cache/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const [entry] = await db
        .select()
        .from(huntCache)
        .where(and(eq(huntCache.id, id), eq(huntCache.orgId, orgId)));
      if (!entry) return res.status(404).json({ message: "Cache entry not found" });
      await db.delete(huntCache).where(eq(huntCache.id, id));
      res.json({ message: "Cache entry deleted" });
    } catch (error) {
      log.error("Delete cache error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete cache entry" });
    }
  });

  app.delete("/api/threat-hunting/cache", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      await db.delete(huntCache).where(eq(huntCache.orgId, orgId));
      res.json({ message: "All cache entries cleared" });
    } catch (error) {
      log.error("Clear cache error", { error: String(error) });
      res.status(500).json({ message: "Failed to clear cache" });
    }
  });

  // =========================================================================
  // DRIFT DETECTION FOR SCHEDULED HUNTS
  // =========================================================================

  app.get("/api/threat-hunting/drifts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const drifts = await db
        .select({
          drift: huntScheduleDrifts,
          huntName: threatHunts.name,
        })
        .from(huntScheduleDrifts)
        .leftJoin(threatHunts, eq(huntScheduleDrifts.huntId, threatHunts.id))
        .where(eq(huntScheduleDrifts.orgId, orgId))
        .orderBy(desc(huntScheduleDrifts.detectedAt))
        .limit(100);
      res.json({ drifts });
    } catch (error) {
      log.error("List drifts error", { error: String(error) });
      res.status(500).json({ message: "Failed to list drift detections" });
    }
  });

  app.patch("/api/threat-hunting/drifts/:id/acknowledge", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const [drift] = await db
        .select()
        .from(huntScheduleDrifts)
        .where(and(eq(huntScheduleDrifts.id, id), eq(huntScheduleDrifts.orgId, orgId)));
      if (!drift) return res.status(404).json({ message: "Drift not found" });

      const [updated] = await db
        .update(huntScheduleDrifts)
        .set({ acknowledged: true })
        .where(eq(huntScheduleDrifts.id, id))
        .returning();
      res.json({ drift: updated });
    } catch (error) {
      log.error("Acknowledge drift error", { error: String(error) });
      res.status(500).json({ message: "Failed to acknowledge drift" });
    }
  });

  // =========================================================================
  // HUNT → INCIDENT ESCALATION (enhanced — already exists, add more data)
  // =========================================================================

  app.post("/api/threat-hunting/hunts/:id/escalate-incident", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));
      if (!hunt) return res.status(404).json({ message: "Hunt not found" });

      // Get latest results
      const results = await db
        .select()
        .from(huntResults)
        .where(and(eq(huntResults.huntId, id), eq(huntResults.orgId, orgId)))
        .orderBy(desc(huntResults.executedAt))
        .limit(5);

      const totalEvents = results.reduce((sum, r) => sum + r.eventCount, 0);
      const severity =
        totalEvents >= 20 ? "critical" : totalEvents >= 10 ? "high" : totalEvents >= 5 ? "medium" : "low";

      const [incident] = await db
        .insert(incidents)
        .values({
          orgId,
          title: `Threat Hunt Escalation: ${hunt.name}`,
          summary: [
            `Escalated from threat hunt "${hunt.name}" (${hunt.queryType.toUpperCase()}).`,
            `Hypothesis: ${hunt.hypothesis || "N/A"}`,
            `Total events across ${results.length} execution(s): ${totalEvents}`,
            `MITRE Techniques: ${(hunt.mitreTechniques as string[]).join(", ") || "N/A"}`,
            `Query: ${hunt.queryText.substring(0, 500)}`,
          ].join("\n"),
          severity,
          status: "open",
          mitreTechniques: hunt.mitreTechniques as string[] | undefined,
          affectedAssets:
            results.length > 0 && results[0].eventsJson
              ? { huntResults: (results[0].eventsJson as unknown[]).slice(0, 30) }
              : undefined,
        })
        .returning();

      // Link latest result to incident
      if (results.length > 0) {
        await db.update(huntResults).set({ linkedIncidentId: incident.id }).where(eq(huntResults.id, results[0].id));
      }

      res.json({ incident, message: "Incident created with full hunt context" });
    } catch (error) {
      log.error("Escalate hunt error", { error: String(error) });
      res.status(500).json({ message: "Failed to escalate hunt to incident" });
    }
  });

  // =========================================================================
  // HUNT → DETECTION RULE CONVERSION (Sigma rule generation)
  // =========================================================================

  app.post("/api/threat-hunting/hunts/:id/to-detection-rule", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, id), eq(threatHunts.orgId, orgId)));
      if (!hunt) return res.status(404).json({ message: "Hunt not found" });

      // Generate a Sigma rule from the hunt query
      const sigmaRule = generateSigmaFromHunt(hunt);

      res.json({
        sigmaRule,
        huntName: hunt.name,
        huntQueryType: hunt.queryType,
        message: "Sigma detection rule generated from hunt query",
      });
    } catch (error) {
      log.error("Convert to detection rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to convert hunt to detection rule" });
    }
  });

  // =========================================================================
  // COMMUNITY HUNT SHARING
  // =========================================================================

  app.get("/api/threat-hunting/community", isAuthenticated, async (req, res) => {
    try {
      const category = req.query.category ? String(req.query.category) : undefined;
      const conditions = [];
      if (category && ALLOWED_CATEGORIES.includes(category)) {
        conditions.push(eq(communityHuntShares.category, category));
      }

      const shares = await db
        .select()
        .from(communityHuntShares)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(communityHuntShares.upvotes))
        .limit(100);
      res.json({ shares });
    } catch (error) {
      log.error("List community shares error", { error: String(error) });
      res.status(500).json({ message: "Failed to list community shares" });
    }
  });

  app.post("/api/threat-hunting/community", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { huntId, title, description, category } = req.body;

      if (!huntId || typeof huntId !== "string") {
        return res.status(400).json({ message: "Hunt ID is required" });
      }
      if (!title || typeof title !== "string") {
        return res.status(400).json({ message: "Title is required" });
      }

      const [hunt] = await db
        .select()
        .from(threatHunts)
        .where(and(eq(threatHunts.id, huntId), eq(threatHunts.orgId, orgId)));
      if (!hunt) return res.status(404).json({ message: "Hunt not found" });

      // Compute anonymized stats from past results
      const results = await db
        .select()
        .from(huntResults)
        .where(and(eq(huntResults.huntId, huntId), eq(huntResults.orgId, orgId)))
        .orderBy(desc(huntResults.executedAt))
        .limit(20);

      const totalRuns = results.length;
      const detectionRate = totalRuns > 0 ? results.filter((r) => r.eventCount > 0).length / totalRuns : 0;
      const avgExecutionMs =
        totalRuns > 0 ? Math.round(results.reduce((s, r) => s + (r.executionDurationMs || 0), 0) / totalRuns) : 0;

      const [share] = await db
        .insert(communityHuntShares)
        .values({
          orgId,
          huntId,
          title: title.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 2000) : null,
          queryType: hunt.queryType,
          queryText: hunt.queryText,
          category: category && ALLOWED_CATEGORIES.includes(category) ? category : null,
          mitreTechniques: hunt.mitreTechniques,
          tags: hunt.tags,
          anonymizedStats: { detectionRate: Math.round(detectionRate * 100), avgExecutionMs, totalRuns },
          sharedBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      res.status(201).json({ share });
    } catch (error) {
      log.error("Community share error", { error: String(error) });
      res.status(500).json({ message: "Failed to share hunt to community" });
    }
  });

  app.post("/api/threat-hunting/community/:id/upvote", isAuthenticated, async (req, res) => {
    try {
      const id = String(req.params.id);
      const [share] = await db.select().from(communityHuntShares).where(eq(communityHuntShares.id, id));
      if (!share) return res.status(404).json({ message: "Community share not found" });

      const [updated] = await db
        .update(communityHuntShares)
        .set({ upvotes: sql`${communityHuntShares.upvotes} + 1` })
        .where(eq(communityHuntShares.id, id))
        .returning();
      res.json({ share: updated });
    } catch (error) {
      log.error("Upvote community share error", { error: String(error) });
      res.status(500).json({ message: "Failed to upvote" });
    }
  });

  app.post("/api/threat-hunting/community/:id/download", isAuthenticated, async (req, res) => {
    try {
      const id = String(req.params.id);
      const [share] = await db.select().from(communityHuntShares).where(eq(communityHuntShares.id, id));
      if (!share) return res.status(404).json({ message: "Community share not found" });

      await db
        .update(communityHuntShares)
        .set({ downloads: sql`${communityHuntShares.downloads} + 1` })
        .where(eq(communityHuntShares.id, id));

      res.json({
        queryType: share.queryType,
        queryText: share.queryText,
        mitreTechniques: share.mitreTechniques,
        tags: share.tags,
      });
    } catch (error) {
      log.error("Download community share error", { error: String(error) });
      res.status(500).json({ message: "Failed to download" });
    }
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function computeNextRun(cadence: string, hourUtc: number, dayOfWeek: number | null): Date {
  const now = new Date();
  const next = new Date(now);
  next.setUTCHours(hourUtc, 0, 0, 0);

  switch (cadence) {
    case "daily":
      if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
      break;
    case "weekly":
      if (dayOfWeek !== null) {
        const diff = (dayOfWeek - now.getUTCDay() + 7) % 7;
        next.setUTCDate(next.getUTCDate() + (diff === 0 && next <= now ? 7 : diff));
      } else {
        next.setUTCDate(next.getUTCDate() + 7);
      }
      break;
    case "biweekly":
      next.setUTCDate(next.getUTCDate() + 14);
      break;
    case "monthly":
      next.setUTCMonth(next.getUTCMonth() + 1);
      break;
    default:
      next.setUTCDate(next.getUTCDate() + 1);
  }

  return next;
}

// ─── Helper: Generate Sigma rule from hunt ──────────────────────────────────

function generateSigmaFromHunt(hunt: {
  name: string;
  description: string | null;
  queryType: string;
  queryText: string;
  mitreTechniques: unknown;
  tags: unknown;
}): string {
  const techniques = Array.isArray(hunt.mitreTechniques) ? (hunt.mitreTechniques as string[]) : [];
  const tags = Array.isArray(hunt.tags) ? (hunt.tags as string[]) : [];

  const mitreLines = techniques.map((t) => `    - attack.${t.toLowerCase()}`).join("\n");
  const tagLines = tags.map((t) => `    - ${t}`).join("\n");

  if (hunt.queryType === "sigma") {
    // Already a Sigma rule — return with metadata wrapper
    return [
      `# Auto-generated Sigma Detection Rule`,
      `# Source: Threat Hunt "${hunt.name}"`,
      `# Generated: ${new Date().toISOString()}`,
      ``,
      hunt.queryText,
    ].join("\n");
  }

  // Convert other query types to Sigma-style YAML
  const sigmaYaml = [
    `title: "Detection Rule: ${hunt.name.replace(/"/g, '\\"')}"`,
    `id: ${crypto.randomUUID()}`,
    `status: experimental`,
    `description: "${(hunt.description || "Converted from threat hunt query").replace(/"/g, '\\"')}"`,
    `author: SecureNexus Auto-Conversion`,
    `date: ${new Date().toISOString().split("T")[0]}`,
    ``,
    `# Original query type: ${hunt.queryType}`,
    `# Original query:`,
    ...hunt.queryText.split("\n").map((line) => `#   ${line}`),
    ``,
    `logsource:`,
    `    category: generic`,
    `    product: any`,
    ``,
    `detection:`,
    `    selection:`,
    `        # Adapt these fields based on your log sources`,
    `        EventID|contains: "*"`,
    `    condition: selection`,
    ``,
    `level: medium`,
    ``,
    ...(techniques.length > 0 ? [`tags:`, mitreLines] : []),
    ...(tags.length > 0 ? [`  # Custom tags:`, tagLines] : []),
  ].join("\n");

  return sigmaYaml;
}
