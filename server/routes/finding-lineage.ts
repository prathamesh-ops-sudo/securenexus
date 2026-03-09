import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getFindings,
  getFindingById,
  filterFindings,
  getLineageStats,
  ingestFinding,
  updateFindingStatus,
  getOwners,
  getEvidenceForFinding,
  getRemediationsForFinding,
} from "../finding-lineage-engine";
import type { FindingSeverity, FindingSource, FindingStatus, LineageFilter } from "../finding-lineage-engine";

const VALID_SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

const VALID_SOURCES: FindingSource[] = [
  "sast",
  "dast",
  "sca",
  "container_scan",
  "iac_scan",
  "secret_scan",
  "cloud_config",
  "runtime",
  "pentest",
  "manual",
];

const VALID_STATUSES: FindingStatus[] = ["open", "in_progress", "remediated", "suppressed", "false_positive"];

function validateSeverity(val: string): val is FindingSeverity {
  return VALID_SEVERITIES.includes(val as FindingSeverity);
}

function validateSource(val: string): val is FindingSource {
  return VALID_SOURCES.includes(val as FindingSource);
}

function validateStatus(val: string): val is FindingStatus {
  return VALID_STATUSES.includes(val as FindingStatus);
}

export function registerFindingLineageRoutes(app: Express): void {
  app.get("/api/finding-lineage", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const findings = getFindings(orgId);
      res.json(findings);
    } catch (error) {
      logger.child("routes").error("List findings error", { error: String(error) });
      res.status(500).json({ message: "Failed to list findings" });
    }
  });

  app.get("/api/finding-lineage/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = getLineageStats(orgId);
      res.json(stats);
    } catch (error) {
      logger.child("routes").error("Lineage stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch lineage stats" });
    }
  });

  app.get("/api/finding-lineage/owners", isAuthenticated, async (_req, res) => {
    try {
      const owners = getOwners();
      res.json(owners);
    } catch (error) {
      logger.child("routes").error("List owners error", { error: String(error) });
      res.status(500).json({ message: "Failed to list owners" });
    }
  });

  app.get("/api/finding-lineage/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const finding = getFindingById(id, orgId);
      if (!finding) {
        return res.status(404).json({ message: "Finding not found" });
      }
      res.json(finding);
    } catch (error) {
      logger.child("routes").error("Get finding error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch finding" });
    }
  });

  app.get("/api/finding-lineage/:id/evidence", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const evidence = getEvidenceForFinding(id, orgId);
      res.json(evidence);
    } catch (error) {
      logger.child("routes").error("Get evidence error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch evidence" });
    }
  });

  app.get("/api/finding-lineage/:id/remediations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const remediations = getRemediationsForFinding(id, orgId);
      res.json(remediations);
    } catch (error) {
      logger.child("routes").error("Get remediations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch remediations" });
    }
  });

  app.post("/api/finding-lineage/filter", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body as LineageFilter;

      if (body.severity) {
        for (const s of body.severity) {
          if (!validateSeverity(s)) {
            return res.status(400).json({ message: `Invalid severity: ${s}` });
          }
        }
      }
      if (body.source) {
        for (const s of body.source) {
          if (!validateSource(s)) {
            return res.status(400).json({ message: `Invalid source: ${s}` });
          }
        }
      }
      if (body.status) {
        for (const s of body.status) {
          if (!validateStatus(s)) {
            return res.status(400).json({ message: `Invalid status: ${s}` });
          }
        }
      }
      if (
        body.minRiskScore !== undefined &&
        (typeof body.minRiskScore !== "number" || body.minRiskScore < 0 || body.minRiskScore > 1)
      ) {
        return res.status(400).json({ message: "minRiskScore must be between 0 and 1" });
      }
      if (
        body.maxRiskScore !== undefined &&
        (typeof body.maxRiskScore !== "number" || body.maxRiskScore < 0 || body.maxRiskScore > 1)
      ) {
        return res.status(400).json({ message: "maxRiskScore must be between 0 and 1" });
      }

      const results = filterFindings(body, orgId);
      res.json(results);
    } catch (error) {
      logger.child("routes").error("Filter findings error", { error: String(error) });
      res.status(500).json({ message: "Failed to filter findings" });
    }
  });

  app.post("/api/finding-lineage/ingest", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;

      if (!body.title || typeof body.title !== "string") {
        return res.status(400).json({ message: "title is required" });
      }
      if (!body.severity || !validateSeverity(body.severity)) {
        return res.status(400).json({ message: "Valid severity is required" });
      }
      if (!body.source || !validateSource(body.source)) {
        return res.status(400).json({ message: "Valid source is required" });
      }
      if (!body.sourceLocation || !body.sourceLocation.repo) {
        return res.status(400).json({ message: "sourceLocation with repo is required" });
      }
      if (!body.deployedAsset || !body.deployedAsset.assetName) {
        return res.status(400).json({ message: "deployedAsset with assetName is required" });
      }
      if (!body.owner || !body.owner.ownerName) {
        return res.status(400).json({ message: "owner with ownerName is required" });
      }

      const finding = ingestFinding(orgId, body);
      res.status(201).json(finding);
    } catch (error) {
      logger.child("routes").error("Ingest finding error", { error: String(error) });
      res.status(500).json({ message: "Failed to ingest finding" });
    }
  });

  app.patch("/api/finding-lineage/:id/status", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { status } = req.body as { status: string };

      if (!status || !validateStatus(status)) {
        return res.status(400).json({ message: `Invalid status: ${status}` });
      }

      const updated = updateFindingStatus(id, status, orgId);
      if (!updated) {
        return res.status(404).json({ message: "Finding not found" });
      }
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update finding status error", { error: String(error) });
      res.status(500).json({ message: "Failed to update finding status" });
    }
  });
}
