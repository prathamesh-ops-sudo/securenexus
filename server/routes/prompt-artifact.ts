import type { Express } from "express";
import { z } from "zod";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext } from "../rbac";
import { runInvestigation, getInvestigation, listInvestigations, getSuggestedPrompts } from "../prompt-artifact-engine";

const runInvestigationSchema = z.object({
  prompt: z.string().min(1, "Prompt is required").max(2000, "Prompt must be under 2000 characters"),
});

export function registerPromptArtifactRoutes(app: Express): void {
  app.post("/api/prompt-artifact/investigate", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const parsed = runInvestigationSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Invalid request",
          errors: parsed.error.flatten().fieldErrors,
        });
      }

      const { prompt } = parsed.data;
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        return res.status(403).json({ message: "Organization context required" });
      }
      const investigation = runInvestigation(prompt, orgId);
      res.json(investigation);
    } catch (error) {
      logger.child("routes").error("Prompt-to-artifact investigation error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to run investigation" });
    }
  });

  app.get("/api/prompt-artifact/investigations", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        return res.status(403).json({ message: "Organization context required" });
      }
      const investigations = listInvestigations(orgId);
      res.json(investigations);
    } catch (error) {
      logger.child("routes").error("List investigations error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to list investigations" });
    }
  });

  app.get("/api/prompt-artifact/investigations/:id", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        return res.status(403).json({ message: "Organization context required" });
      }
      const id = String(req.params.id);
      const investigation = getInvestigation(id, orgId);
      if (!investigation) return res.status(404).json({ message: "Investigation not found" });
      res.json(investigation);
    } catch (error) {
      logger.child("routes").error("Get investigation error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to fetch investigation" });
    }
  });

  app.get("/api/prompt-artifact/suggestions", isAuthenticated, async (_req, res) => {
    try {
      const suggestions = getSuggestedPrompts();
      res.json(suggestions);
    } catch (error) {
      logger.child("routes").error("Suggestions error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to fetch suggestions" });
    }
  });
}
