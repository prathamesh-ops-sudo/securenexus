import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertCspmAccountSchema, insertEndpointAssetSchema } from "@shared/schema";
import { runCspmScan, runDspmScan, createDriftBaseline, runDriftDetection, remediationEngine } from "../cspm-scanner";
import { calculateEndpointRisk, generateTelemetry, seedEndpointAssets } from "../endpoint-telemetry";
import { calculatePostureScore } from "../posture-engine";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";

export function registerEndpointsRoutes(app: Express): void {
  // ── CSPM Routes ──
  app.get(
    "/api/cspm/accounts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accounts = await storage.getCspmAccounts(orgId);
        res.json(accounts);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch CSPM accounts" });
      }
    },
  );

  app.post(
    "/api/cspm/accounts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = { ...req.body, orgId };
        const parsed = insertCspmAccountSchema.safeParse(body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid CSPM account data", errors: parsed.error.flatten() });
        }
        const account = await storage.createCspmAccount(parsed.data);
        res.status(201).json(account);
      } catch (error) {
        res.status(500).json({ message: "Failed to create CSPM account" });
      }
    },
  );

  app.patch(
    "/api/cspm/accounts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getCspmAccount(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const account = await storage.updateCspmAccount(p(req.params.id), req.body);
        if (!account) return res.status(404).json({ message: "CSPM account not found" });
        res.json(account);
      } catch (error) {
        res.status(500).json({ message: "Failed to update CSPM account" });
      }
    },
  );

  app.delete(
    "/api/cspm/accounts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getCspmAccount(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const deleted = await storage.deleteCspmAccount(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "CSPM account not found" });
        res.json({ message: "CSPM account deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete CSPM account" });
      }
    },
  );

  app.get(
    "/api/cspm/scans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const scans = await storage.getCspmScans(orgId, accountId);
        res.json(scans);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch CSPM scans" });
      }
    },
  );

  app.post(
    "/api/cspm/scans/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        try {
          await runCspmScan(orgId, p(req.params.accountId));
          res.json({ message: "Scan completed successfully" });
        } catch (scanErr) {
          logger.child("routes").error("CSPM scan error", { error: String(scanErr) });
          res.status(502).json({ message: "Scan failed", error: String(scanErr) });
        }
      } catch (error) {
        res.status(500).json({ message: "Failed to start CSPM scan" });
      }
    },
  );

  app.get(
    "/api/cspm/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const scanId = req.query.scanId as string | undefined;
        const severity = req.query.severity as string | undefined;
        const findings = await storage.getCspmFindings(orgId, scanId, severity);
        res.json(findings);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch CSPM findings" });
      }
    },
  );

  app.patch(
    "/api/cspm/findings/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const findings = await storage.getCspmFindings(orgId);
        const existing = findings.find((f) => f.id === p(req.params.id));
        if (!existing) return res.status(404).json({ message: "CSPM finding not found" });
        const finding = await storage.updateCspmFinding(p(req.params.id), req.body);
        if (!finding) return res.status(404).json({ message: "CSPM finding not found" });
        res.json(finding);
      } catch (error) {
        res.status(500).json({ message: "Failed to update CSPM finding" });
      }
    },
  );

  // ── CSPM Drift Detection Routes ──
  app.post(
    "/api/cspm/drift/baseline/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const count = await createDriftBaseline(orgId, p(req.params.accountId));
        res.json({ message: "Baseline created", baselineCount: count });
      } catch (error) {
        logger.child("routes").error("Drift baseline error", { error: String(error) });
        res.status(500).json({ message: "Failed to create drift baseline" });
      }
    },
  );

  app.get(
    "/api/cspm/drift/baselines",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const baselines = await storage.getCspmDriftBaselines(orgId, accountId);
        res.json(baselines);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch drift baselines" });
      }
    },
  );

  app.post(
    "/api/cspm/drift/detect/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const driftCount = await runDriftDetection(orgId, p(req.params.accountId));
        res.json({ message: "Drift detection complete", driftEventsDetected: driftCount });
      } catch (error) {
        logger.child("routes").error("Drift detection error", { error: String(error) });
        res.status(500).json({ message: String(error) });
      }
    },
  );

  app.get(
    "/api/cspm/drift/events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const status = req.query.status as string | undefined;
        const events = await storage.getCspmDriftEvents(orgId, accountId, status);
        res.json(events);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch drift events" });
      }
    },
  );

  // ── CSPM DSPM Routes ──
  app.post(
    "/api/cspm/dspm/scan/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const result = await runDspmScan(orgId, p(req.params.accountId));
        res.json({ message: "DSPM scan complete", ...result });
      } catch (error) {
        logger.child("routes").error("DSPM scan error", { error: String(error) });
        res.status(500).json({ message: "DSPM scan failed", error: String(error) });
      }
    },
  );

  app.get(
    "/api/cspm/dspm/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const sensitivityLevel = req.query.sensitivityLevel as string | undefined;
        const findings = await storage.getCspmDspmFindings(orgId, accountId, sensitivityLevel);
        res.json(findings);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch DSPM findings" });
      }
    },
  );

  // ── CSPM Attack Path Routes ──
  app.get(
    "/api/cspm/attack-paths",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const severity = req.query.severity as string | undefined;
        const paths = await storage.getCspmAttackPaths(orgId, severity);
        res.json(paths);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch attack paths" });
      }
    },
  );

  // ── CSPM Remediation Routes ──
  app.get(
    "/api/cspm/remediation/playbooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const playbooks = remediationEngine.getAllPlaybooks();
        res.json(playbooks);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch playbooks" });
      }
    },
  );

  app.get(
    "/api/cspm/remediation/playbooks/:ruleId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const ruleId = Array.isArray(req.params.ruleId) ? req.params.ruleId[0] : req.params.ruleId;
        const playbooks = remediationEngine.getPlaybooks(ruleId);
        res.json(playbooks);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch playbooks for rule" });
      }
    },
  );

  app.post(
    "/api/cspm/remediation/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { accountId, findingId, playbookId, resourceId } = req.body as {
          accountId: string;
          findingId?: string;
          playbookId: string;
          resourceId: string;
        };

        if (!accountId || !playbookId || !resourceId) {
          return res.status(400).json({ message: "accountId, playbookId, and resourceId are required" });
        }

        const account = await storage.getCspmAccount(accountId);
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });

        const config = (account.config || {}) as Record<string, unknown>;
        const regions = account.regions && account.regions.length > 0 ? account.regions : ["us-east-1"];

        const awsConfig = {
          accessKeyId: (config.accessKeyId as string) || process.env.AWS_ACCESS_KEY_ID || "",
          secretAccessKey: (config.secretAccessKey as string) || process.env.AWS_SECRET_ACCESS_KEY || "",
          regions: regions as string[],
        };

        const result = await remediationEngine.executePlaybook(playbookId, resourceId, awsConfig);

        // Store remediation record
        const playbookInfo = remediationEngine.getAllPlaybooks().find((pb) => pb.id === playbookId);
        await storage.createCspmRemediation({
          orgId,
          accountId,
          findingId: findingId || null,
          playbookId,
          playbookName: playbookInfo?.name || playbookId,
          resourceId,
          ruleId: result.ruleId,
          status: result.status,
          actionsExecuted: result.actionsExecuted,
          actionsTotal: result.actionsTotal,
          error: result.error || null,
          details: result.details,
        });

        res.json(result);
      } catch (error) {
        logger.child("routes").error("Remediation execution error", { error: String(error) });
        res.status(500).json({ message: "Remediation failed", error: String(error) });
      }
    },
  );

  app.get(
    "/api/cspm/remediations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const status = req.query.status as string | undefined;
        const remediations = await storage.getCspmRemediations(orgId, accountId, status);
        res.json(remediations);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch remediations" });
      }
    },
  );

  // ── Endpoint Telemetry Routes ──
  app.get(
    "/api/endpoints",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await storage.getEndpointAssets(orgId);
        res.json(assets);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint assets" });
      }
    },
  );

  app.get(
    "/api/endpoints/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        res.json(asset);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint asset" });
      }
    },
  );

  app.post(
    "/api/endpoints/seed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await seedEndpointAssets(orgId);
        res.status(201).json(assets);
      } catch (error) {
        res.status(500).json({ message: "Failed to seed endpoint assets" });
      }
    },
  );

  app.post(
    "/api/endpoints",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    enforcePlanLimit("endpoints_monitored"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = { ...req.body, orgId };
        const parsed = insertEndpointAssetSchema.safeParse(body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid endpoint asset data", errors: parsed.error.flatten() });
        }
        const asset = await storage.createEndpointAsset(parsed.data);
        res.status(201).json(asset);
      } catch (error) {
        res.status(500).json({ message: "Failed to create endpoint asset" });
      }
    },
  );

  app.patch(
    "/api/endpoints/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getEndpointAsset(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const asset = await storage.updateEndpointAsset(p(req.params.id), req.body);
        if (!asset) return res.status(404).json({ message: "Endpoint asset not found" });
        res.json(asset);
      } catch (error) {
        res.status(500).json({ message: "Failed to update endpoint asset" });
      }
    },
  );

  app.delete(
    "/api/endpoints/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getEndpointAsset(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const deleted = await storage.deleteEndpointAsset(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Endpoint asset not found" });
        res.json({ message: "Endpoint asset deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete endpoint asset" });
      }
    },
  );

  app.get(
    "/api/endpoints/:id/telemetry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const telemetry = await storage.getEndpointTelemetry(p(req.params.id));
        res.json(telemetry);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint telemetry" });
      }
    },
  );

  app.post(
    "/api/endpoints/:id/telemetry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const telemetry = await generateTelemetry(orgId, p(req.params.id));
        res.status(201).json(telemetry);
      } catch (error) {
        res.status(500).json({ message: "Failed to generate endpoint telemetry" });
      }
    },
  );

  app.post(
    "/api/endpoints/:id/risk",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const riskScore = await calculateEndpointRisk(p(req.params.id));
        res.json({ riskScore });
      } catch (error) {
        res.status(500).json({ message: "Failed to calculate endpoint risk" });
      }
    },
  );

  // ── Posture Score Routes ──
  app.get(
    "/api/posture/scores",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const scores = await storage.getPostureScores(orgId);
        res.json(scores);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch posture scores" });
      }
    },
  );

  app.post(
    "/api/posture/calculate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const score = await calculatePostureScore(orgId);
        res.status(201).json(score);
      } catch (error) {
        res.status(500).json({ message: "Failed to calculate posture score" });
      }
    },
  );

  app.get(
    "/api/posture/latest",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const score = await storage.getLatestPostureScore(orgId);
        if (!score) return res.json(null);
        res.json(score);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch latest posture score" });
      }
    },
  );
}
