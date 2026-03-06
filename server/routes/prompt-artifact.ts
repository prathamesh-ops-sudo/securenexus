import type { Express } from "express";
import { z } from "zod";
import { logger } from "./shared";
import { isAuthenticated } from "../auth";
import { runInvestigation, getInvestigation, listInvestigations, getSuggestedPrompts } from "../prompt-artifact-engine";

const runInvestigationSchema = z.object({
  prompt: z.string().min(1, "Prompt is required").max(2000, "Prompt must be under 2000 characters"),
  orgId: z.string().nullable().optional(),
});

export function registerPromptArtifactRoutes(app: Express): void {
  app.post("/api/prompt-artifact/investigate", isAuthenticated, async (req, res) => {
    try {
      const parsed = runInvestigationSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Invalid request",
          errors: parsed.error.flatten().fieldErrors,
        });
      }

      const { prompt, orgId } = parsed.data;
      const investigation = runInvestigation(prompt, orgId ?? null);
      res.json(investigation);
    } catch (error) {
      logger.child("routes").error("Prompt-to-artifact investigation error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to run investigation" });
    }
  });

  app.get("/api/prompt-artifact/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const investigations = listInvestigations(orgId ?? null);
      res.json(investigations);
    } catch (error) {
      logger.child("routes").error("List investigations error", {
        error: String(error),
      });
      res.status(500).json({ message: "Failed to list investigations" });
    }
  });

  app.get("/api/prompt-artifact/investigations/:id", isAuthenticated, async (req, res) => {
    try {
      const rawOrgId = req.query.orgId;
      const orgId = typeof rawOrgId === "string" ? rawOrgId : undefined;
      const id = String(req.params.id);
      const investigation = getInvestigation(id, orgId ?? null);
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
