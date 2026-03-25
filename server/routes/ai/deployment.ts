import type { Express, Request, Response } from "express";
import { getOrgId, logger, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole, requireOrgId } from "../../rbac";
import { insertAiDeploymentConfigSchema } from "@shared/schema";

const log = logger.child("routes-ai-deployment");

export function registerAiDeploymentRoutes(app: Express): void {
  // AI Deployment Config Routes
  app.get("/api/ai-deployment/config", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const config = await storage.getAiDeploymentConfig(orgId);
      if (!config) return res.json(null);
      res.json(config);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch AI deployment config" });
    }
  });

  app.put(
    "/api/ai-deployment/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertAiDeploymentConfigSchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid AI deployment config data", errors: parsed.error.flatten() });
        }
        const config = await storage.upsertAiDeploymentConfig(parsed.data);
        res.json(config);
      } catch (error) {
        res.status(500).json({ message: "Failed to upsert AI deployment config" });
      }
    },
  );
}
