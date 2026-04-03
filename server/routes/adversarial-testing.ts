import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { storage } from "../storage";
import {
  getAttackLibrary,
  getTestCaseById,
  type AttackDomain,
  type AttackCategory,
  type TestPhase,
  type TestStatus,
  type RunTrigger,
  type Severity,
  type ScheduleFrequency,
} from "../adversarial-testing-engine";

const VALID_DOMAINS: AttackDomain[] = ["application", "identity", "cloud", "ai_agent"];
const VALID_CATEGORIES: AttackCategory[] = [
  "prompt_injection",
  "evasion",
  "tool_misuse",
  "privilege_escalation",
  "secret_leakage",
  "xss",
  "sqli",
  "ssrf",
  "csrf",
  "auth_bypass",
];
const VALID_PHASES: TestPhase[] = ["pre_production", "production_safe", "post_fix"];
const VALID_STATUSES: TestStatus[] = ["pending", "running", "passed", "failed", "error", "skipped"];
const VALID_TRIGGERS: RunTrigger[] = ["manual", "ci_pipeline", "scheduled", "post_fix"];
const VALID_SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const VALID_FREQUENCIES: ScheduleFrequency[] = ["hourly", "daily", "weekly", "monthly", "on_deploy"];
const VALID_REMEDIATION_STATUSES = ["open", "in_progress", "resolved", "wont_fix"] as const;

export function registerAdversarialTestingRoutes(app: Express): void {
  app.get("/api/adversarial-testing/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [totalExecutions, remediations] = await Promise.all([
        storage.countAdversarialExecutions(orgId),
        storage.getAdversarialRemediations(orgId),
      ]);
      const openRemediations = remediations.filter((r) => r.status === "open" || r.status === "in_progress").length;
      const resolvedRemediations = remediations.filter((r) => r.status === "resolved").length;
      res.json({
        totalExecutions,
        openRemediations,
        resolvedRemediations,
        totalRemediations: remediations.length,
      });
    } catch (error) {
      logger.child("routes").error("Adversarial stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch adversarial testing stats" });
    }
  });

  // Attack library is static reference data — kept on engine
  app.get("/api/adversarial-testing/library", isAuthenticated, async (req, res) => {
    try {
      const domain =
        typeof req.query.domain === "string" && VALID_DOMAINS.includes(req.query.domain as AttackDomain)
          ? (req.query.domain as AttackDomain)
          : undefined;
      const category =
        typeof req.query.category === "string" && VALID_CATEGORIES.includes(req.query.category as AttackCategory)
          ? (req.query.category as AttackCategory)
          : undefined;
      const phase =
        typeof req.query.phase === "string" && VALID_PHASES.includes(req.query.phase as TestPhase)
          ? (req.query.phase as TestPhase)
          : undefined;
      res.json(getAttackLibrary(domain, category, phase));
    } catch (error) {
      logger.child("routes").error("Attack library error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack library" });
    }
  });

  app.get("/api/adversarial-testing/library/:id", isAuthenticated, async (req, res) => {
    try {
      const id = String(req.params.id);
      const tc = getTestCaseById(id);
      if (!tc) return res.status(404).json({ message: "Test case not found" });
      res.json(tc);
    } catch (error) {
      logger.child("routes").error("Get test case error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch test case" });
    }
  });

  // Executions — persisted to DB
  app.get("/api/adversarial-testing/executions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 100;
      const executions = await storage.getAdversarialExecutions(orgId, limit);
      // Apply client-side filters if provided
      let filtered = executions;
      if (typeof req.query.testCaseId === "string") {
        filtered = filtered.filter((e) => e.testCaseId === req.query.testCaseId);
      }
      if (typeof req.query.status === "string" && VALID_STATUSES.includes(req.query.status as TestStatus)) {
        filtered = filtered.filter((e) => e.status === req.query.status);
      }
      if (typeof req.query.domain === "string" && VALID_DOMAINS.includes(req.query.domain as AttackDomain)) {
        filtered = filtered.filter((e) => e.domain === req.query.domain);
      }
      if (typeof req.query.category === "string" && VALID_CATEGORIES.includes(req.query.category as AttackCategory)) {
        filtered = filtered.filter((e) => e.category === req.query.category);
      }
      res.json(filtered);
    } catch (error) {
      logger.child("routes").error("List executions error", { error: String(error) });
      res.status(500).json({ message: "Failed to list test executions" });
    }
  });

  app.post("/api/adversarial-testing/run", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { testCaseId, trigger } = req.body as { testCaseId?: string; trigger?: string };
      if (!testCaseId || typeof testCaseId !== "string") {
        return res.status(400).json({ message: "testCaseId is required" });
      }
      const tc = getTestCaseById(testCaseId);
      if (!tc) return res.status(404).json({ message: "Test case not found" });
      if (!tc.enabled) return res.status(400).json({ message: "Test case is disabled" });

      const validTrigger: RunTrigger =
        trigger && VALID_TRIGGERS.includes(trigger as RunTrigger) ? (trigger as RunTrigger) : "manual";

      const execution = await storage.createAdversarialExecution({
        orgId,
        testCaseId,
        testCaseName: tc.name,
        domain: tc.domain,
        category: tc.category,
        phase: tc.phase || "pre_production",
        status: "running",
        trigger: validTrigger,
        severity: tc.severity || "medium",
        result: {},
        startedAt: new Date(),
      });
      res.status(201).json(execution);
    } catch (error) {
      logger.child("routes").error("Run test case error", { error: String(error) });
      res.status(500).json({ message: "Failed to run test case" });
    }
  });

  app.post("/api/adversarial-testing/run-batch", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { testCaseIds, trigger } = req.body as { testCaseIds?: string[]; trigger?: string };
      if (!Array.isArray(testCaseIds) || testCaseIds.length === 0) {
        return res.status(400).json({ message: "testCaseIds must be a non-empty array" });
      }
      if (testCaseIds.length > 50) {
        return res.status(400).json({ message: "Maximum 50 test cases per batch" });
      }
      const validTrigger: RunTrigger =
        trigger && VALID_TRIGGERS.includes(trigger as RunTrigger) ? (trigger as RunTrigger) : "manual";

      const executions = await Promise.all(
        testCaseIds.map(async (tcId) => {
          const tc = getTestCaseById(tcId);
          if (!tc || !tc.enabled) return null;
          return storage.createAdversarialExecution({
            orgId,
            testCaseId: tcId,
            testCaseName: tc.name,
            domain: tc.domain,
            category: tc.category,
            phase: tc.phase || "pre_production",
            status: "running",
            trigger: validTrigger,
            severity: tc.severity || "medium",
            result: {},
            startedAt: new Date(),
          });
        }),
      );
      const created = executions.filter(Boolean);
      res.status(201).json({ count: created.length, executions: created });
    } catch (error) {
      logger.child("routes").error("Run batch error", { error: String(error) });
      res.status(500).json({ message: "Failed to run batch" });
    }
  });

  // Schedules — persisted to DB
  app.get("/api/adversarial-testing/schedules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const schedules = await storage.getAdversarialSchedules(orgId);
      res.json(schedules);
    } catch (error) {
      logger.child("routes").error("List schedules error", { error: String(error) });
      res.status(500).json({ message: "Failed to list schedules" });
    }
  });

  app.post("/api/adversarial-testing/schedules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;
      if (!body.name || typeof body.name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!body.frequency || !VALID_FREQUENCIES.includes(body.frequency)) {
        return res.status(400).json({ message: `frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` });
      }
      if (!Array.isArray(body.testCaseIds) || body.testCaseIds.length === 0) {
        return res.status(400).json({ message: "testCaseIds must be a non-empty array" });
      }
      const schedule = await storage.createAdversarialSchedule({
        orgId,
        name: body.name,
        frequency: body.frequency,
        testCaseIds: body.testCaseIds,
        enabled: body.enabled !== false,
        nextRunAt: body.nextRunAt ? new Date(body.nextRunAt) : new Date(Date.now() + 86400000),
        config: {
          description: body.description || "",
          domains: Array.isArray(body.domains)
            ? body.domains.filter((d: string) => VALID_DOMAINS.includes(d as AttackDomain))
            : [],
          categories: Array.isArray(body.categories)
            ? body.categories.filter((c: string) => VALID_CATEGORIES.includes(c as AttackCategory))
            : [],
          phase: body.phase && VALID_PHASES.includes(body.phase) ? body.phase : "pre_production",
        },
      });
      res.status(201).json(schedule);
    } catch (error) {
      logger.child("routes").error("Create schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create schedule" });
    }
  });

  app.patch("/api/adversarial-testing/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const body = req.body;
      const updates: Record<string, unknown> = {};
      if (body.name !== undefined) {
        if (typeof body.name !== "string") return res.status(400).json({ message: "name must be a string" });
        updates.name = body.name;
      }
      if (body.frequency !== undefined) {
        if (!VALID_FREQUENCIES.includes(body.frequency))
          return res.status(400).json({ message: `frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` });
        updates.frequency = body.frequency;
      }
      if (body.enabled !== undefined) {
        updates.enabled = body.enabled === true;
      }
      if (body.testCaseIds !== undefined) {
        if (!Array.isArray(body.testCaseIds)) return res.status(400).json({ message: "testCaseIds must be an array" });
        updates.testCaseIds = body.testCaseIds;
      }
      const updated = await storage.updateAdversarialSchedule(id, orgId, updates);
      if (!updated) return res.status(404).json({ message: "Schedule not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to update schedule" });
    }
  });

  app.delete("/api/adversarial-testing/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const deleted = await storage.deleteAdversarialSchedule(id, orgId);
      if (!deleted) return res.status(404).json({ message: "Schedule not found" });
      res.json({ message: "Schedule deleted" });
    } catch (error) {
      logger.child("routes").error("Delete schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete schedule" });
    }
  });

  // Remediations — persisted to DB
  app.get("/api/adversarial-testing/remediations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const statusFilter =
        typeof req.query.status === "string" &&
        VALID_REMEDIATION_STATUSES.includes(req.query.status as (typeof VALID_REMEDIATION_STATUSES)[number])
          ? req.query.status
          : undefined;
      const remediations = await storage.getAdversarialRemediations(orgId, statusFilter);
      // Apply additional client-side filters
      let filtered = remediations;
      if (typeof req.query.severity === "string" && VALID_SEVERITIES.includes(req.query.severity as Severity)) {
        filtered = filtered.filter((r) => r.severity === req.query.severity);
      }
      res.json(filtered);
    } catch (error) {
      logger.child("routes").error("List remediations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list remediations" });
    }
  });

  app.patch("/api/adversarial-testing/remediations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const body = req.body;
      if (body.status !== undefined && !VALID_REMEDIATION_STATUSES.includes(body.status)) {
        return res.status(400).json({ message: `status must be one of: ${VALID_REMEDIATION_STATUSES.join(", ")}` });
      }
      const updates: Record<string, unknown> = {};
      if (body.status !== undefined) {
        updates.status = body.status;
        if (body.status === "resolved") updates.resolvedAt = new Date();
      }
      if (body.assignee !== undefined) updates.assignee = body.assignee;
      if (body.recommendation !== undefined) updates.recommendation = body.recommendation;
      const updated = await storage.updateAdversarialRemediation(id, orgId, updates);
      if (!updated) return res.status(404).json({ message: "Remediation not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to update remediation" });
    }
  });

  app.post("/api/adversarial-testing/remediations/:id/retest", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const remediation = await storage.getAdversarialRemediation(id, orgId);
      if (!remediation) return res.status(404).json({ message: "Remediation not found" });

      // Look up original execution to get correct testCaseId, domain, and category
      const originalExecution = await storage.getAdversarialExecution(remediation.executionId, orgId);
      if (!originalExecution) {
        return res.status(404).json({ message: "Original execution not found, cannot retest" });
      }

      // Create a new execution for the retest
      const execution = await storage.createAdversarialExecution({
        orgId,
        testCaseId: originalExecution.testCaseId,
        testCaseName: remediation.testCaseName,
        domain: originalExecution.domain,
        category: originalExecution.category,
        phase: "post_fix",
        status: "running",
        trigger: "post_fix",
        severity: remediation.severity || "medium",
        result: { retestOfRemediation: id },
        startedAt: new Date(),
      });
      res.status(201).json(execution);
    } catch (error) {
      logger.child("routes").error("Retest remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to retest" });
    }
  });
}
