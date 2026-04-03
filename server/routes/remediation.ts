import type { Express } from "express";
import { getOrgId, logger } from "./shared";
import { isAuthenticated } from "../auth";
import * as remediationStorage from "../storage/remediation";

const log = logger.child("remediation");

export function registerRemediationRoutes(app: Express): void {
  app.get("/api/remediation/fixes", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = typeof req.query.status === "string" ? req.query.status : null;

      const fixes = status
        ? await remediationStorage.getRemediationFixesByStatus(orgId, status)
        : await remediationStorage.getRemediationFixes(orgId);
      res.json(fixes);
    } catch (error) {
      log.error("List remediations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list remediations" });
    }
  });

  app.get("/api/remediation/fixes/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const fix = await remediationStorage.getRemediationFix(id);
      if (!fix || fix.orgId !== orgId) return res.status(404).json({ message: "Remediation not found" });
      res.json(fix);
    } catch (error) {
      log.error("Get remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch remediation" });
    }
  });

  app.post("/api/remediation/fixes", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;
      if (!body.title || typeof body.title !== "string") {
        return res.status(400).json({ message: "title is required" });
      }
      if (!body.type || typeof body.type !== "string") {
        return res.status(400).json({ message: "type is required" });
      }

      const fix = await remediationStorage.createRemediationFix({
        orgId,
        type: body.type,
        title: body.title,
        description: body.description || "",
        priority: body.priority || "medium",
        status: body.status || "suggested",
        finding: body.finding || {},
        codeChange: body.codeChange || null,
        ownerId: body.ownerId || null,
        estimatedEffort: body.estimatedEffort || null,
        mitreTactics: body.mitreTactics || [],
        cweIds: body.cweIds || [],
      });

      res.status(201).json(fix);
    } catch (error) {
      log.error("Create remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to create remediation" });
    }
  });

  app.patch("/api/remediation/fixes/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const existing = await remediationStorage.getRemediationFix(id);
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Remediation not found" });

      const updated = await remediationStorage.updateRemediationFix(id, req.body);
      res.json(updated);
    } catch (error) {
      log.error("Update remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to update remediation" });
    }
  });

  app.delete("/api/remediation/fixes/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const existing = await remediationStorage.getRemediationFix(id);
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Remediation not found" });

      await remediationStorage.deleteRemediationFix(id);
      res.json({ success: true });
    } catch (error) {
      log.error("Delete remediation error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete remediation" });
    }
  });

  app.get("/api/remediation/owners", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const owners = await remediationStorage.getCodeOwnersList(orgId);
      res.json(owners);
    } catch (error) {
      log.error("List code owners error", { error: String(error) });
      res.status(500).json({ message: "Failed to list code owners" });
    }
  });

  app.get("/api/remediation/owners/lookup", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
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
      const owner = await remediationStorage.findCodeOwnerForFile(orgId, sanitizedPath);
      res.json(owner || null);
    } catch (error) {
      log.error("Owner lookup error", { error: String(error) });
      res.status(500).json({ message: "Failed to lookup code owner" });
    }
  });

  app.get("/api/remediation/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const fixes = await remediationStorage.getRemediationFixes(orgId);

      const byPriority: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      const byType: Record<string, number> = {};
      let suggested = 0;
      let applied = 0;
      let dismissed = 0;
      let inProgress = 0;

      for (const fix of fixes) {
        if (fix.priority in byPriority) byPriority[fix.priority]++;
        byType[fix.type] = (byType[fix.type] || 0) + 1;
        if (fix.status === "suggested") suggested++;
        else if (fix.status === "applied") applied++;
        else if (fix.status === "dismissed") dismissed++;
        else if (fix.status === "in_progress") inProgress++;
      }

      res.json({
        totalFindings: fixes.length,
        suggestedFixes: suggested,
        appliedFixes: applied,
        dismissedFixes: dismissed,
        inProgressFixes: inProgress,
        byPriority,
        byType,
        coveragePercent: fixes.length > 0 ? Math.round(((applied + dismissed) / fixes.length) * 100) : 0,
      });
    } catch (error) {
      log.error("Remediation stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch remediation stats" });
    }
  });
}
