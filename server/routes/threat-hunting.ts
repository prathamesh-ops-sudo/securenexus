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
  alerts,
  HUNT_QUERY_TYPES,
  HUNT_STATUSES,
} from "@shared/schema";
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
          status: result.eventCount > 0 ? "completed" : "completed",
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
        .catch(() => {});
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
