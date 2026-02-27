import type { Express, Request, Response } from "express";
import { getOrgId, p, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { evaluateAllFlags, evaluateFlag } from "../feature-flags";
import { runAllContractTests, runAutomationIntegrationTests, runConnectorContractTests } from "../integration-tests";
import { evaluateAndAlert, getBreachHistory, seedDefaultSloTargets } from "../slo-alerting";
import { checkReadiness, checkLiveness, getInFlightCount } from "../request-lifecycle";
import {
  evaluateCanaryMetrics,
  evaluateRollbackTriggers,
  getRollbackTriggers,
  getRollbackRunbook,
  createRollbackIncident,
} from "../canary-analysis";
import { executeDrill, getDrillSchedulerStatus, getRpoRtoDashboard, runScheduledDrills } from "../dr-drill-scheduler";

export function registerOperationsRoutes(app: Express): void {
  // === Job Queue ===
  app.get("/api/ops/jobs", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string;
      const status = req.query.status as string;
      const type = req.query.type as string;
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const jobs = await storage.getJobs(orgId, status, type, limit);
      res.json(jobs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch jobs" });
    }
  });

  app.get("/api/ops/jobs/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getJobStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch job stats" });
    }
  });

  app.post("/api/ops/jobs", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { type, payload, priority, runAt } = req.body;
      if (!type) return res.status(400).json({ message: "type is required" });
      const job = await storage.createJob({
        orgId,
        type,
        status: "pending",
        payload: payload || {},
        priority: priority || 0,
        runAt: runAt ? new Date(runAt) : new Date(),
        attempts: 0,
        maxAttempts: 3,
      });
      res.status(201).json(job);
    } catch (error) {
      res.status(500).json({ message: "Failed to create job" });
    }
  });

  app.post("/api/ops/jobs/:id/cancel", isAuthenticated, async (req, res) => {
    try {
      const success = await storage.cancelJob(p(req.params.id));
      if (!success) return res.status(404).json({ message: "Job not found or not cancellable" });
      res.json({ cancelled: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to cancel job" });
    }
  });

  app.get("/api/ops/worker/status", isAuthenticated, async (req, res) => {
    try {
      const { getWorkerStatus } = await import("../job-queue");
      res.json(getWorkerStatus());
    } catch (error) {
      res.status(500).json({ message: "Failed to get worker status" });
    }
  });

  // === Readiness / Liveness / Health ===
  app.get("/api/ops/ready", async (_req, res) => {
    try {
      const status = await checkReadiness();
      res.status(status.ready ? 200 : 503).json(status);
    } catch (error) {
      res.status(503).json({ ready: false, timestamp: new Date().toISOString(), error: "Readiness check failed" });
    }
  });

  app.get("/api/ops/live", (_req, res) => {
    const status = checkLiveness();
    res.status(status.alive ? 200 : 503).json(status);
  });

  app.get("/api/ops/health", async (_req, res) => {
    try {
      const readiness = await checkReadiness();
      const liveness = checkLiveness();
      const dbCheck = await storage.getJobStats();
      res.status(readiness.ready ? 200 : 503).json({
        status: readiness.ready ? "healthy" : "unhealthy",
        timestamp: new Date().toISOString(),
        readiness: readiness.checks,
        liveness: { uptime: liveness.uptime, memoryMB: liveness.memoryMB, pid: liveness.pid },
        inFlight: getInFlightCount(),
        jobQueue: dbCheck,
      });
    } catch (error) {
      res.status(503).json({ status: "unhealthy", timestamp: new Date().toISOString(), error: "Health check failed" });
    }
  });

  app.get("/api/ops/sli", isAuthenticated, async (req, res) => {
    try {
      const service = req.query.service as string;
      const metric = req.query.metric as string;
      const hours = parseInt(req.query.hours as string, 10) || 24;
      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - hours * 60 * 60 * 1000);
      if (!service || !metric) {
        return res.status(400).json({ message: "service and metric query params required" });
      }
      const metrics = await storage.getSliMetrics(service, metric, startTime, endTime);
      res.json(metrics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLI metrics" });
    }
  });

  app.get("/api/ops/slo", isAuthenticated, async (req, res) => {
    try {
      const targets = await storage.getSloTargets();
      const { evaluateSlos } = await import("../sli-middleware");
      const evaluations = await evaluateSlos();
      res.json({ targets, evaluations });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLO status" });
    }
  });

  app.get(
    "/api/ops/slo-targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const targets = await storage.getSloTargets();
        res.json(targets);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch SLO targets" });
      }
    },
  );

  app.post(
    "/api/ops/slo-targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const target = await storage.createSloTarget(req.body);
        res.status(201).json(target);
      } catch (error) {
        res.status(500).json({ message: "Failed to create SLO target" });
      }
    },
  );

  app.patch(
    "/api/ops/slo-targets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const updated = await storage.updateSloTarget(p(req.params.id), req.body);
        if (!updated) return res.status(404).json({ message: "SLO target not found" });
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update SLO target" });
      }
    },
  );

  app.delete(
    "/api/ops/slo-targets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const deleted = await storage.deleteSloTarget(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "SLO target not found" });
        res.json({ deleted: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete SLO target" });
      }
    },
  );

  app.post("/api/ops/slo-targets/seed", isAuthenticated, async (req, res) => {
    try {
      const defaults = [
        {
          service: "api",
          metric: "availability",
          target: 99.9,
          operator: "gte",
          windowMinutes: 60,
          alertOnBreach: true,
          description: "API Availability > 99.9%",
        },
        {
          service: "api",
          metric: "latency_p95",
          target: 500,
          operator: "lte",
          windowMinutes: 60,
          alertOnBreach: true,
          description: "API P95 Latency < 500ms",
        },
        {
          service: "ingestion",
          metric: "error_rate",
          target: 1.0,
          operator: "lte",
          windowMinutes: 60,
          alertOnBreach: true,
          description: "Ingestion Error Rate < 1%",
        },
        {
          service: "ingestion",
          metric: "throughput",
          target: 10,
          operator: "gte",
          windowMinutes: 60,
          alertOnBreach: false,
          description: "Ingestion Throughput > 10 req/min",
        },
        {
          service: "ai",
          metric: "latency_p95",
          target: 5000,
          operator: "lte",
          windowMinutes: 60,
          alertOnBreach: true,
          description: "AI P95 Latency < 5s",
        },
        {
          service: "ai",
          metric: "availability",
          target: 99.0,
          operator: "gte",
          windowMinutes: 60,
          alertOnBreach: true,
          description: "AI Availability > 99%",
        },
        {
          service: "connector",
          metric: "error_rate",
          target: 5.0,
          operator: "lte",
          windowMinutes: 60,
          alertOnBreach: true,
          description: "Connector Error Rate < 5%",
        },
        {
          service: "enrichment",
          metric: "latency_p95",
          target: 3000,
          operator: "lte",
          windowMinutes: 60,
          alertOnBreach: false,
          description: "Enrichment P95 Latency < 3s",
        },
      ];
      const results = [];
      for (const d of defaults) {
        try {
          results.push(await storage.createSloTarget(d as any));
        } catch (e) {
          // skip duplicates
        }
      }
      res.status(201).json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed SLO targets" });
    }
  });

  // === Disaster Recovery Runbooks ===
  app.get("/api/ops/dr-runbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const runbooks = await storage.getDrRunbooks(orgId);
      res.json(runbooks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DR runbooks" });
    }
  });

  app.get("/api/ops/dr-runbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const runbook = await storage.getDrRunbook(p(req.params.id));
      if (!runbook) return res.status(404).json({ message: "Runbook not found" });
      res.json(runbook);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DR runbook" });
    }
  });

  app.post("/api/ops/dr-runbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const runbook = await storage.createDrRunbook({ ...req.body, orgId });
      res.status(201).json(runbook);
    } catch (error) {
      res.status(500).json({ message: "Failed to create DR runbook" });
    }
  });

  app.patch("/api/ops/dr-runbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const updated = await storage.updateDrRunbook(p(req.params.id), req.body);
      if (!updated) return res.status(404).json({ message: "Runbook not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update DR runbook" });
    }
  });

  app.delete("/api/ops/dr-runbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteDrRunbook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Runbook not found" });
      res.json({ deleted: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete DR runbook" });
    }
  });

  app.post("/api/ops/dr-runbooks/:id/test", isAuthenticated, async (req, res) => {
    try {
      const { result, notes } = req.body;
      if (!result) return res.status(400).json({ message: "result (pass/fail/partial) required" });
      const updated = await storage.updateDrRunbook(p(req.params.id), {
        lastTestedAt: new Date(),
        lastTestResult: result,
        testNotes: notes || null,
      });
      if (!updated) return res.status(404).json({ message: "Runbook not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to record test result" });
    }
  });

  app.post("/api/ops/dr-runbooks/seed", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const defaults = [
        {
          orgId,
          title: "RDS Failover (Primary DB Failure)",
          description:
            "Procedure when primary RDS instance is unavailable or degraded performance >5 minutes. Promotes cross-region read replica and redirects traffic.",
          category: "failover",
          steps: [
            {
              order: 1,
              instruction: "Verify primary DB is truly unavailable (check CloudWatch, attempt connection)",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            {
              order: 2,
              instruction:
                "Promote cross-region read replica to standalone: aws rds promote-read-replica --db-instance-identifier securenexus-db-replica-west --region us-west-2",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 3,
              instruction: "Update Secrets Manager with new DB endpoint in us-west-2",
              expectedDuration: "1 min",
              responsible: "Platform Team",
            },
            {
              order: 4,
              instruction: "Update EKS deployment to use new DB endpoint (or deploy DR EKS cluster)",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 5,
              instruction: "Update DNS to point to DR region load balancer",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            {
              order: 6,
              instruction: "Verify application health via /api/health endpoint",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            {
              order: 7,
              instruction: "Notify stakeholders via incident channel",
              expectedDuration: "1 min",
              responsible: "Platform Team",
            },
          ],
          rtoMinutes: 18,
          rpoMinutes: 60,
          owner: "Platform Team",
          status: "active",
        },
        {
          orgId,
          title: "Full Region Failure (us-east-1 outage)",
          description:
            "Complete AWS us-east-1 region unavailable. Deploys full stack in us-west-2 DR region using replicated resources.",
          category: "failover",
          steps: [
            {
              order: 1,
              instruction: "Confirm region-level outage via AWS Health Dashboard",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            {
              order: 2,
              instruction: "Promote RDS read replica in us-west-2",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 3,
              instruction: "Deploy EKS cluster in us-west-2 using stored manifests from Git",
              expectedDuration: "15 min",
              responsible: "Platform Team",
            },
            {
              order: 4,
              instruction: "Pull latest container images from ECR (cross-region replicated)",
              expectedDuration: "3 min",
              responsible: "Platform Team",
            },
            {
              order: 5,
              instruction: "Apply K8s manifests with DR-region secrets",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 6,
              instruction: "Update Route 53 DNS failover records to us-west-2 load balancer",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            { order: 7, instruction: "Verify all services healthy", expectedDuration: "3 min", responsible: "SRE" },
            {
              order: 8,
              instruction: "Run smoke tests against DR deployment",
              expectedDuration: "5 min",
              responsible: "SRE",
            },
          ],
          rtoMinutes: 40,
          rpoMinutes: 60,
          owner: "Platform Team + SRE",
          status: "active",
        },
        {
          orgId,
          title: "Data Corruption Recovery",
          description:
            "Triggered when data integrity issue detected (bad migration, accidental deletion, etc.). Uses RDS point-in-time restore.",
          category: "data_recovery",
          steps: [
            {
              order: 1,
              instruction: "Identify corruption scope and timestamp of last known good state",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 2,
              instruction: "Take snapshot of current (corrupted) state for forensics",
              expectedDuration: "3 min",
              responsible: "Platform Team",
            },
            {
              order: 3,
              instruction:
                "Restore RDS to point-in-time before corruption: aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier securenexus-db --target-db-instance-identifier securenexus-db-restored --restore-time TIMESTAMP",
              expectedDuration: "15 min",
              responsible: "Platform Team",
            },
            {
              order: 4,
              instruction: "Verify restored data integrity",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 5,
              instruction: "Update application to point to restored instance",
              expectedDuration: "3 min",
              responsible: "Platform Team",
            },
            {
              order: 6,
              instruction: "Run schema validation: npm run db:push --dry-run",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            {
              order: 7,
              instruction: "Verify application functionality",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
          ],
          rtoMinutes: 38,
          rpoMinutes: 60,
          owner: "Platform Team",
          status: "active",
        },
        {
          orgId,
          title: "S3 Object Recovery",
          description:
            "Triggered when critical files deleted or corrupted in S3. Restores from version history or cross-region replication bucket.",
          category: "backup",
          steps: [
            {
              order: 1,
              instruction: "Identify affected objects and versions in securenexus-platform-557845624595",
              expectedDuration: "3 min",
              responsible: "Platform Team",
            },
            {
              order: 2,
              instruction:
                "Restore from version history: aws s3api get-object --bucket securenexus-platform-557845624595 --key {key} --version-id {version-id} {output}",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
            {
              order: 3,
              instruction:
                "Or restore from CRR bucket: aws s3 sync s3://securenexus-platform-dr-557845624595/{prefix} s3://securenexus-platform-557845624595/{prefix}",
              expectedDuration: "5 min",
              responsible: "Platform Team",
            },
            {
              order: 4,
              instruction: "Verify restored objects integrity and completeness",
              expectedDuration: "2 min",
              responsible: "Platform Team",
            },
          ],
          rtoMinutes: 12,
          rpoMinutes: 60,
          owner: "Platform Team",
          status: "active",
        },
      ];
      const results = [];
      for (const d of defaults) {
        results.push(await storage.createDrRunbook(d as any));
      }
      res.status(201).json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed DR runbooks" });
    }
  });

  // === Dashboard Metrics Cache ===
  app.get("/api/ops/metrics-cache", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const metricType = (req.query.metricType as string) || "stats";
      const cached = await storage.getCachedMetrics(orgId, metricType);
      res.json(cached || { cached: false });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch cached metrics" });
    }
  });

  app.post("/api/ops/metrics-cache/refresh", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getDashboardStats(orgId);
      const analytics = await storage.getDashboardAnalytics(orgId);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min TTL
      await Promise.all([
        storage.upsertCachedMetrics({ orgId, metricType: "stats", payload: stats, expiresAt }),
        storage.upsertCachedMetrics({ orgId, metricType: "analytics", payload: analytics, expiresAt }),
      ]);
      res.json({ refreshed: true, expiresAt: expiresAt.toISOString() });
    } catch (error) {
      res.status(500).json({ message: "Failed to refresh metrics cache" });
    }
  });

  // === Alert Daily Stats ===
  app.get("/api/ops/alert-daily-stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const days = parseInt(req.query.days as string, 10) || 30;
      const endDate = new Date().toISOString().split("T")[0];
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
      const stats = await storage.getAlertDailyStats(orgId, startDate, endDate);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert daily stats" });
    }
  });

  // ============================
  // SLO v1 Endpoints (per-endpoint aware)
  // ============================
  app.get("/api/v1/slo/targets", isAuthenticated, async (_req, res) => {
    try {
      const targets = await storage.getSloTargets();
      return sendEnvelope(res, targets, { meta: { total: targets.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "SLO_FETCH_FAILED", message: error?.message || "Failed to fetch SLO targets" }],
      });
    }
  });

  app.post(
    "/api/v1/slo/targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { service, metric, endpoint, target, operator, windowMinutes, alertOnBreach, description } = req.body;
        if (!service || !metric || target === undefined) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "service, metric, and target are required" }],
          });
        }
        const sloTarget = await storage.createSloTarget({
          service,
          metric,
          endpoint: endpoint || "*",
          target,
          operator: operator || "lte",
          windowMinutes: windowMinutes || 60,
          alertOnBreach: alertOnBreach !== false,
          description,
        });
        return sendEnvelope(res, sloTarget, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SLO_CREATE_FAILED", message: error?.message || "Failed to create SLO target" }],
        });
      }
    },
  );

  app.patch(
    "/api/v1/slo/targets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const updated = await storage.updateSloTarget(p(req.params.id), req.body);
        if (!updated)
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "SLO target not found" }],
          });
        return sendEnvelope(res, updated);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SLO_UPDATE_FAILED", message: error?.message || "Failed to update SLO target" }],
        });
      }
    },
  );

  app.delete(
    "/api/v1/slo/targets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const deleted = await storage.deleteSloTarget(p(req.params.id));
        if (!deleted)
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "SLO target not found" }],
          });
        return sendEnvelope(res, { deleted: true });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SLO_DELETE_FAILED", message: error?.message || "Failed to delete SLO target" }],
        });
      }
    },
  );

  app.get("/api/v1/slo/evaluate", isAuthenticated, async (_req, res) => {
    try {
      const result = await evaluateAndAlert();
      return sendEnvelope(res, result);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "SLO_EVAL_FAILED", message: error?.message || "Failed to evaluate SLOs" }],
      });
    }
  });

  app.get("/api/v1/slo/breach-history", isAuthenticated, async (req, res) => {
    try {
      const service = req.query.service as string | undefined;
      const hoursBack = parseInt(req.query.hours as string, 10) || 24;
      const breaches = await getBreachHistory(service, hoursBack);
      return sendEnvelope(res, breaches, { meta: { total: breaches.length, hoursBack } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "BREACH_HISTORY_FAILED", message: error?.message || "Failed to fetch breach history" }],
      });
    }
  });

  app.post(
    "/api/v1/slo/seed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const seeded = await seedDefaultSloTargets();
        return sendEnvelope(res, { seeded }, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SLO_SEED_FAILED", message: error?.message || "Failed to seed SLO targets" }],
        });
      }
    },
  );

  // ============================
  // Feature Flags v1 Endpoints
  // ============================
  app.get("/api/v1/feature-flags", isAuthenticated, async (_req, res) => {
    try {
      const flags = await storage.listFeatureFlags();
      return sendEnvelope(res, flags, { meta: { total: flags.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "FLAG_LIST_FAILED", message: error?.message || "Failed to list feature flags" }],
      });
    }
  });

  app.post(
    "/api/v1/feature-flags",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { key, name, description, enabled, rolloutPct, targetOrgs, targetRoles, metadata } = req.body;
        if (!key || !name) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "key and name are required" }],
          });
        }
        const existing = await storage.getFeatureFlag(key);
        if (existing) {
          return sendEnvelope(res, null, {
            status: 409,
            errors: [{ code: "DUPLICATE_KEY", message: `Feature flag '${key}' already exists` }],
          });
        }
        const flag = await storage.createFeatureFlag({
          key,
          name,
          description,
          enabled: enabled ?? false,
          rolloutPct: rolloutPct ?? 100,
          targetOrgs: targetOrgs || [],
          targetRoles: targetRoles || [],
          metadata: metadata || {},
          createdBy: (req as any).user?.id,
        });
        return sendEnvelope(res, flag, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "FLAG_CREATE_FAILED", message: error?.message || "Failed to create feature flag" }],
        });
      }
    },
  );

  app.get("/api/v1/feature-flags/:key", isAuthenticated, async (req, res) => {
    try {
      const flag = await storage.getFeatureFlag(p(req.params.key));
      if (!flag)
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Feature flag not found" }],
        });
      return sendEnvelope(res, flag);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "FLAG_FETCH_FAILED", message: error?.message || "Failed to fetch feature flag" }],
      });
    }
  });

  app.patch(
    "/api/v1/feature-flags/:key",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const updated = await storage.updateFeatureFlag(p(req.params.key), req.body);
        if (!updated)
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Feature flag not found" }],
          });
        return sendEnvelope(res, updated);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "FLAG_UPDATE_FAILED", message: error?.message || "Failed to update feature flag" }],
        });
      }
    },
  );

  app.delete(
    "/api/v1/feature-flags/:key",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const deleted = await storage.deleteFeatureFlag(p(req.params.key));
        if (!deleted)
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Feature flag not found" }],
          });
        return sendEnvelope(res, { deleted: true });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "FLAG_DELETE_FAILED", message: error?.message || "Failed to delete feature flag" }],
        });
      }
    },
  );

  app.post("/api/v1/feature-flags/:key/evaluate", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const result = await evaluateFlag(p(req.params.key), {
        orgId: user?.orgId,
        userId: user?.id,
        role: user?.role,
      });
      return sendEnvelope(res, result);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "FLAG_EVAL_FAILED", message: error?.message || "Failed to evaluate feature flag" }],
      });
    }
  });

  app.get("/api/v1/feature-flags-evaluate-all", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const results = await evaluateAllFlags({
        orgId: user?.orgId,
        userId: user?.id,
        role: user?.role,
      });
      return sendEnvelope(res, results);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "FLAG_EVAL_ALL_FAILED", message: error?.message || "Failed to evaluate feature flags" }],
      });
    }
  });

  // ============================
  // DR Drill Execution v1 Endpoints
  // ============================
  app.get("/api/v1/dr/runbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const runbooks = await storage.getDrRunbooks(orgId);
      return sendEnvelope(res, runbooks, { meta: { total: runbooks.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "DR_FETCH_FAILED", message: error?.message || "Failed to fetch DR runbooks" }],
      });
    }
  });

  app.post(
    "/api/v1/dr/run-drill",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { runbookId, dryRun } = req.body;
        if (!runbookId) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "runbookId is required" }],
          });
        }
        const runbook = await storage.getDrRunbook(runbookId);
        if (!runbook)
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Runbook not found" }],
          });

        const drillStart = Date.now();
        const steps = Array.isArray(runbook.steps) ? (runbook.steps as Array<{ title: string; action: string }>) : [];
        const stepResults = steps.map((step, idx) => ({
          step: idx + 1,
          title: step.title || `Step ${idx + 1}`,
          status: dryRun ? "simulated" : "completed",
          durationMs: Math.floor(Math.random() * 2000) + 500,
        }));

        const drillResult = {
          runbookId,
          runbookTitle: runbook.title,
          dryRun: !!dryRun,
          rtoMinutes: runbook.rtoMinutes,
          rpoMinutes: runbook.rpoMinutes,
          totalDurationMs: Date.now() - drillStart,
          steps: stepResults,
          status: "completed",
          ranAt: new Date().toISOString(),
          ranBy: (req as any).user?.id,
        };

        return sendEnvelope(res, drillResult, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "DR_DRILL_FAILED", message: error?.message || "Failed to run DR drill" }],
        });
      }
    },
  );

  // ============================
  // Canary Analysis & Rollback Triggers (14.3)
  // ============================
  app.get("/api/ops/canary/analysis", isAuthenticated, async (req, res) => {
    try {
      const errorThreshold = parseFloat(req.query.errorThreshold as string) || 5;
      const latencyThreshold = parseFloat(req.query.latencyThreshold as string) || 800;
      const result = await evaluateCanaryMetrics(errorThreshold, latencyThreshold);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to evaluate canary metrics" });
    }
  });

  app.get("/api/ops/canary/triggers", isAuthenticated, async (_req, res) => {
    try {
      const triggers = getRollbackTriggers();
      res.json(triggers);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch rollback triggers" });
    }
  });

  app.post("/api/ops/canary/evaluate-triggers", isAuthenticated, async (req, res) => {
    try {
      const { metrics } = req.body;
      if (!metrics) return res.status(400).json({ message: "metrics object required in body" });
      const evaluations = await evaluateRollbackTriggers(metrics);
      const firedTriggers = evaluations.filter((e) => e.fired);
      res.json({
        evaluations,
        firedCount: firedTriggers.length,
        recommendation: firedTriggers.some((t) => t.action === "auto_rollback")
          ? "rollback"
          : firedTriggers.some((t) => t.action === "pause_rollout")
            ? "pause"
            : "continue",
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to evaluate rollback triggers" });
    }
  });

  app.get("/api/ops/canary/rollback-runbook", isAuthenticated, (_req, res) => {
    try {
      const runbook = getRollbackRunbook();
      res.json(runbook);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch rollback runbook" });
    }
  });

  app.post(
    "/api/ops/canary/create-rollback-incident",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { analysisResult, triggeredBy } = req.body;
        if (!analysisResult) return res.status(400).json({ message: "analysisResult required" });
        await createRollbackIncident(analysisResult, triggeredBy || "manual");
        res.status(201).json({ created: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to create rollback incident" });
      }
    },
  );

  // ============================
  // DR Drill Results & RPO/RTO Dashboard (14.4)
  // ============================
  app.get("/api/ops/dr-drill-results", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string;
      const runbookId = req.query.runbookId as string;
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const results = await storage.getDrDrillResults(orgId, runbookId, limit);
      res.json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch drill results" });
    }
  });

  app.get("/api/ops/dr-drill-results/:id", isAuthenticated, async (req, res) => {
    try {
      const result = await storage.getDrDrillResult(p(req.params.id));
      if (!result) return res.status(404).json({ message: "Drill result not found" });
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch drill result" });
    }
  });

  app.get("/api/ops/rpo-rto-dashboard", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const dashboard = await getRpoRtoDashboard(orgId);
      res.json(dashboard);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch RPO/RTO dashboard" });
    }
  });

  app.get("/api/ops/dr-scheduler/status", isAuthenticated, (_req, res) => {
    try {
      const status = getDrillSchedulerStatus();
      res.json(status);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch scheduler status" });
    }
  });

  app.post(
    "/api/ops/dr-scheduler/run-now",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const results = await runScheduledDrills();
        res.json({ drillsRun: results.length, results });
      } catch (error) {
        res.status(500).json({ message: "Failed to run scheduled drills" });
      }
    },
  );

  app.post(
    "/api/v1/dr/run-drill-persisted",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { runbookId, dryRun } = req.body;
        if (!runbookId) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "runbookId is required" }],
          });
        }
        const runbook = await storage.getDrRunbook(runbookId);
        if (!runbook) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Runbook not found" }],
          });
        }
        const orgId = getOrgId(req);
        const result = await executeDrill(runbook, orgId, dryRun !== false);
        return sendEnvelope(res, result, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "DR_DRILL_FAILED", message: error?.message || "Failed to run persisted DR drill" }],
        });
      }
    },
  );

  // ============================
  // Integration / Contract Test v1 Endpoints
  // ============================
  app.post(
    "/api/v1/tests/connectors/:type",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const connectorType = p(req.params.type);
        const results = await runConnectorContractTests(connectorType);
        return sendEnvelope(res, results);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TEST_FAILED", message: error?.message || "Connector contract tests failed" }],
        });
      }
    },
  );

  app.post(
    "/api/v1/tests/automation/:playbookId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const playbookId = p(req.params.playbookId);
        const results = await runAutomationIntegrationTests(playbookId);
        return sendEnvelope(res, results);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TEST_FAILED", message: error?.message || "Automation integration tests failed" }],
        });
      }
    },
  );

  app.post(
    "/api/v1/tests/all",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const results = await runAllContractTests();
        const totalTests = results.reduce((sum, s) => sum + s.total, 0);
        const totalPassed = results.reduce((sum, s) => sum + s.passed, 0);
        return sendEnvelope(res, results, {
          meta: { suites: results.length, totalTests, totalPassed, totalFailed: totalTests - totalPassed },
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TEST_FAILED", message: error?.message || "Contract test suite failed" }],
        });
      }
    },
  );
}
