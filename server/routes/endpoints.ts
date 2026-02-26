import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertCspmAccountSchema, insertEndpointAssetSchema } from "@shared/schema";
import { runCspmScan } from "../cspm-scanner";
import { calculateEndpointRisk, generateTelemetry, seedEndpointAssets } from "../endpoint-telemetry";
import { calculatePostureScore } from "../posture-engine";

export function registerEndpointsRoutes(app: Express): void {
  // ── CSPM Routes ──
  app.get("/api/cspm/accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const accounts = await storage.getCspmAccounts(orgId);
      res.json(accounts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM accounts" });
    }
  });

  app.post("/api/cspm/accounts", isAuthenticated, async (req, res) => {
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
  });

  app.patch("/api/cspm/accounts/:id", isAuthenticated, async (req, res) => {
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
  });

  app.delete("/api/cspm/accounts/:id", isAuthenticated, async (req, res) => {
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
  });

  app.get("/api/cspm/scans", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const accountId = req.query.accountId as string | undefined;
      const scans = await storage.getCspmScans(orgId, accountId);
      res.json(scans);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM scans" });
    }
  });

  app.post("/api/cspm/scans/:accountId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const account = await storage.getCspmAccount(p(req.params.accountId));
      if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      runCspmScan(orgId, p(req.params.accountId)).catch(err => logger.child("routes").error("CSPM scan error", { error: String(err) }));
      res.json({ message: "Scan started" });
    } catch (error) {
      res.status(500).json({ message: "Failed to start CSPM scan" });
    }
  });

  app.get("/api/cspm/findings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scanId = req.query.scanId as string | undefined;
      const severity = req.query.severity as string | undefined;
      const findings = await storage.getCspmFindings(orgId, scanId, severity);
      res.json(findings);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM findings" });
    }
  });

  app.patch("/api/cspm/findings/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const findings = await storage.getCspmFindings(orgId);
      const existing = findings.find(f => f.id === p(req.params.id));
      if (!existing) return res.status(404).json({ message: "CSPM finding not found" });
      const finding = await storage.updateCspmFinding(p(req.params.id), req.body);
      if (!finding) return res.status(404).json({ message: "CSPM finding not found" });
      res.json(finding);
    } catch (error) {
      res.status(500).json({ message: "Failed to update CSPM finding" });
    }
  });

  // ── Endpoint Telemetry Routes ──
  app.get("/api/endpoints", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await storage.getEndpointAssets(orgId);
      res.json(assets);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint assets" });
    }
  });

  app.get("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint asset" });
    }
  });

  app.post("/api/endpoints/seed", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await seedEndpointAssets(orgId);
      res.status(201).json(assets);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed endpoint assets" });
    }
  });

  app.post("/api/endpoints", isAuthenticated, async (req, res) => {
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
  });

  app.patch("/api/endpoints/:id", isAuthenticated, async (req, res) => {
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
  });

  app.delete("/api/endpoints/:id", isAuthenticated, async (req, res) => {
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
  });

  app.get("/api/endpoints/:id/telemetry", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const telemetry = await storage.getEndpointTelemetry(p(req.params.id));
      res.json(telemetry);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint telemetry" });
    }
  });

  app.post("/api/endpoints/:id/telemetry", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const telemetry = await generateTelemetry(orgId, p(req.params.id));
      res.status(201).json(telemetry);
    } catch (error) {
      res.status(500).json({ message: "Failed to generate endpoint telemetry" });
    }
  });

  app.post("/api/endpoints/:id/risk", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const riskScore = await calculateEndpointRisk(p(req.params.id));
      res.json({ riskScore });
    } catch (error) {
      res.status(500).json({ message: "Failed to calculate endpoint risk" });
    }
  });

  // ── Posture Score Routes ──
  app.get("/api/posture/scores", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scores = await storage.getPostureScores(orgId);
      res.json(scores);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch posture scores" });
    }
  });

  app.post("/api/posture/calculate", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const score = await calculatePostureScore(orgId);
      res.status(201).json(score);
    } catch (error) {
      res.status(500).json({ message: "Failed to calculate posture score" });
    }
  });

  app.get("/api/posture/latest", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const score = await storage.getLatestPostureScore(orgId);
      if (!score) return res.status(404).json({ message: "No posture score found" });
      res.json(score);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch latest posture score" });
    }
  });

}
