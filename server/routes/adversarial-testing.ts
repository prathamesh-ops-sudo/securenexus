import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getAttackLibrary,
  getTestCaseById,
  getTestExecutions,
  runTestCase,
  runBatch,
  retestRemediation,
  getTestSchedules,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  getRemediationQueue,
  updateRemediation,
  getAdversarialStats,
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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(getAdversarialStats(orgId));
    } catch (error) {
      logger.child("routes").error("Adversarial stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch adversarial testing stats" });
    }
  });

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

  app.get("/api/adversarial-testing/executions", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const filters: {
        testCaseId?: string;
        status?: TestStatus;
        domain?: AttackDomain;
        category?: AttackCategory;
      } = {};
      if (typeof req.query.testCaseId === "string") filters.testCaseId = req.query.testCaseId;
      if (typeof req.query.status === "string" && VALID_STATUSES.includes(req.query.status as TestStatus))
        filters.status = req.query.status as TestStatus;
      if (typeof req.query.domain === "string" && VALID_DOMAINS.includes(req.query.domain as AttackDomain))
        filters.domain = req.query.domain as AttackDomain;
      if (typeof req.query.category === "string" && VALID_CATEGORIES.includes(req.query.category as AttackCategory))
        filters.category = req.query.category as AttackCategory;
      res.json(getTestExecutions(orgId, filters));
    } catch (error) {
      logger.child("routes").error("List executions error", { error: String(error) });
      res.status(500).json({ message: "Failed to list test executions" });
    }
  });

  app.post("/api/adversarial-testing/run", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const { testCaseId, trigger } = req.body as { testCaseId?: string; trigger?: string };
      if (!testCaseId || typeof testCaseId !== "string") {
        return res.status(400).json({ message: "testCaseId is required" });
      }
      const validTrigger: RunTrigger =
        trigger && VALID_TRIGGERS.includes(trigger as RunTrigger) ? (trigger as RunTrigger) : "manual";
      const execution = runTestCase(orgId, testCaseId, validTrigger);
      res.status(201).json(execution);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("TEST_CASE_NOT_FOUND")) return res.status(404).json({ message: "Test case not found" });
      if (errMsg.includes("TEST_CASE_DISABLED")) return res.status(400).json({ message: "Test case is disabled" });
      logger.child("routes").error("Run test case error", { error: errMsg });
      res.status(500).json({ message: "Failed to run test case" });
    }
  });

  app.post("/api/adversarial-testing/run-batch", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const { testCaseIds, trigger } = req.body as { testCaseIds?: string[]; trigger?: string };
      if (!Array.isArray(testCaseIds) || testCaseIds.length === 0) {
        return res.status(400).json({ message: "testCaseIds must be a non-empty array" });
      }
      if (testCaseIds.length > 50) {
        return res.status(400).json({ message: "Maximum 50 test cases per batch" });
      }
      const validTrigger: RunTrigger =
        trigger && VALID_TRIGGERS.includes(trigger as RunTrigger) ? (trigger as RunTrigger) : "manual";
      const executions = runBatch(orgId, testCaseIds, validTrigger);
      res.status(201).json({ count: executions.length, executions });
    } catch (error) {
      logger.child("routes").error("Run batch error", { error: String(error) });
      res.status(500).json({ message: "Failed to run batch" });
    }
  });

  app.get("/api/adversarial-testing/schedules", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(getTestSchedules(orgId));
    } catch (error) {
      logger.child("routes").error("List schedules error", { error: String(error) });
      res.status(500).json({ message: "Failed to list schedules" });
    }
  });

  app.post("/api/adversarial-testing/schedules", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;
      if (!body.name || typeof body.name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!body.frequency || !VALID_FREQUENCIES.includes(body.frequency)) {
        return res.status(400).json({ message: `frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` });
      }
      if (!body.phase || !VALID_PHASES.includes(body.phase)) {
        return res.status(400).json({ message: `phase must be one of: ${VALID_PHASES.join(", ")}` });
      }
      if (!Array.isArray(body.testCaseIds) || body.testCaseIds.length === 0) {
        return res.status(400).json({ message: "testCaseIds must be a non-empty array" });
      }
      const schedule = createSchedule(orgId, {
        name: body.name,
        description: body.description || "",
        frequency: body.frequency,
        domains: Array.isArray(body.domains)
          ? body.domains.filter((d: string) => VALID_DOMAINS.includes(d as AttackDomain))
          : [],
        categories: Array.isArray(body.categories)
          ? body.categories.filter((c: string) => VALID_CATEGORIES.includes(c as AttackCategory))
          : [],
        phase: body.phase,
        enabled: body.enabled !== false,
        nextRunAt: body.nextRunAt || new Date(Date.now() + 86400000).toISOString(),
        testCaseIds: body.testCaseIds,
      });
      res.status(201).json(schedule);
    } catch (error) {
      logger.child("routes").error("Create schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create schedule" });
    }
  });

  app.patch("/api/adversarial-testing/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const body = req.body;
      const sanitized: Record<string, unknown> = {};
      if (body.name !== undefined) {
        if (typeof body.name !== "string") return res.status(400).json({ message: "name must be a string" });
        sanitized.name = body.name;
      }
      if (body.description !== undefined) {
        sanitized.description = typeof body.description === "string" ? body.description : "";
      }
      if (body.frequency !== undefined) {
        if (!VALID_FREQUENCIES.includes(body.frequency))
          return res.status(400).json({ message: `frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` });
        sanitized.frequency = body.frequency;
      }
      if (body.enabled !== undefined) {
        sanitized.enabled = body.enabled === true;
      }
      if (body.domains !== undefined) {
        sanitized.domains = Array.isArray(body.domains)
          ? body.domains.filter((d: string) => VALID_DOMAINS.includes(d as AttackDomain))
          : [];
      }
      if (body.categories !== undefined) {
        sanitized.categories = Array.isArray(body.categories)
          ? body.categories.filter((c: string) => VALID_CATEGORIES.includes(c as AttackCategory))
          : [];
      }
      if (body.testCaseIds !== undefined) {
        if (!Array.isArray(body.testCaseIds)) return res.status(400).json({ message: "testCaseIds must be an array" });
        sanitized.testCaseIds = body.testCaseIds;
      }
      const updated = updateSchedule(orgId, id, sanitized);
      if (!updated) return res.status(404).json({ message: "Schedule not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to update schedule" });
    }
  });

  app.delete("/api/adversarial-testing/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const deleted = deleteSchedule(orgId, id);
      if (!deleted) return res.status(404).json({ message: "Schedule not found" });
      res.json({ message: "Schedule deleted" });
    } catch (error) {
      logger.child("routes").error("Delete schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete schedule" });
    }
  });

  app.get("/api/adversarial-testing/remediations", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const filters: {
        status?: (typeof VALID_REMEDIATION_STATUSES)[number];
        category?: AttackCategory;
        severity?: Severity;
      } = {};
      if (typeof req.query.status === "string" && VALID_REMEDIATION_STATUSES.includes(req.query.status as any))
        filters.status = req.query.status as any;
      if (typeof req.query.category === "string" && VALID_CATEGORIES.includes(req.query.category as AttackCategory))
        filters.category = req.query.category as AttackCategory;
      if (typeof req.query.severity === "string" && VALID_SEVERITIES.includes(req.query.severity as Severity))
        filters.severity = req.query.severity as Severity;
      res.json(getRemediationQueue(orgId, filters));
    } catch (error) {
      logger.child("routes").error("List remediations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list remediations" });
    }
  });

  app.patch("/api/adversarial-testing/remediations/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const body = req.body;
      if (body.status !== undefined && !VALID_REMEDIATION_STATUSES.includes(body.status)) {
        return res.status(400).json({ message: `status must be one of: ${VALID_REMEDIATION_STATUSES.join(", ")}` });
      }
      const updated = updateRemediation(orgId, id, body);
      if (!updated) return res.status(404).json({ message: "Remediation not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to update remediation" });
    }
  });

  app.post("/api/adversarial-testing/remediations/:id/retest", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const execution = retestRemediation(orgId, id);
      res.status(201).json(execution);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("REMEDIATION_NOT_FOUND")) return res.status(404).json({ message: "Remediation not found" });
      if (errMsg.includes("TEST_CASE_NOT_FOUND"))
        return res.status(404).json({ message: "Associated test case not found" });
      logger.child("routes").error("Retest remediation error", { error: errMsg });
      res.status(500).json({ message: "Failed to retest" });
    }
  });
}
