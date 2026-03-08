import type { Express } from "express";
import { logger } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getRemediations,
  getRemediationById,
  getCodeOwners,
  getCodeOwnerForFile,
  getRemediationStats,
} from "../remediation-engine";

export function registerRemediationRoutes(app: Express): void {
  app.get("/api/remediation/fixes", isAuthenticated, async (req, res) => {
    try {
      const rawOrgId = req.query.orgId;
      const orgId = typeof rawOrgId === "string" ? rawOrgId : undefined;
      const fixes = getRemediations(orgId ?? null);
      res.json(fixes);
    } catch (error) {
      logger.child("routes").error("List remediations error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to list remediations" });
    }
  });

  app.get("/api/remediation/fixes/:id", isAuthenticated, async (req, res) => {
    try {
      const rawOrgId = req.query.orgId;
      const orgId = typeof rawOrgId === "string" ? rawOrgId : undefined;
      const id = String(req.params.id);
      const fix = getRemediationById(id, orgId ?? null);
      if (!fix) return res.status(404).json({ message: "Remediation not found" });
      res.json(fix);
    } catch (error) {
      logger.child("routes").error("Get remediation error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to fetch remediation" });
    }
  });

  app.get("/api/remediation/owners", isAuthenticated, async (req, res) => {
    try {
      const rawOrgId = req.query.orgId;
      const orgId = typeof rawOrgId === "string" ? rawOrgId : undefined;
      const owners = getCodeOwners(orgId ?? null);
      res.json(owners);
    } catch (error) {
      logger.child("routes").error("List code owners error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to list code owners" });
    }
  });

  app.get("/api/remediation/owners/lookup", isAuthenticated, async (req, res) => {
    try {
      const rawFilePath = req.query.filePath;
      if (typeof rawFilePath !== "string" || rawFilePath.length === 0) {
        return res.status(400).json({ message: "filePath query parameter is required" });
      }
      if (/\.\.[\\/]|[\\/]\.\./.test(rawFilePath) || rawFilePath.includes("\0")) {
        return res.status(400).json({ message: "Invalid filePath: path traversal sequences are not allowed" });
      }
      const sanitizedPath = rawFilePath
        .replace(/\\/g, "/")
        .replace(/\/{2,}/g, "/")
        .replace(/^\/+/, "");
      const owner = getCodeOwnerForFile(sanitizedPath);
      res.json(owner);
    } catch (error) {
      logger.child("routes").error("Owner lookup error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to lookup code owner" });
    }
  });

  app.get("/api/remediation/stats", isAuthenticated, async (req, res) => {
    try {
      const rawOrgId = req.query.orgId;
      const orgId = typeof rawOrgId === "string" ? rawOrgId : undefined;
      const stats = getRemediationStats(orgId ?? null);
      res.json(stats);
    } catch (error) {
      logger.child("routes").error("Remediation stats error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to fetch remediation stats" });
    }
  });
}
