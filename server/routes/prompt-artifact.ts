import type { Express } from "express";
import { z } from "zod";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext } from "../rbac";
import {
  runInvestigation,
  getInvestigation,
  listInvestigations,
  getSuggestedPrompts,
  getTemplates,
  reviewApproval,
  getPendingApprovals,
  updateArtifactLogic,
} from "../prompt-artifact-engine";

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

  app.get("/api/prompt-artifact/templates", isAuthenticated, async (_req, res) => {
    try {
      const templates = getTemplates();
      res.json(templates);
    } catch (error) {
      logger.child("routes").error("Templates error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch templates" });
    }
  });

  app.get("/api/prompt-artifact/approvals/pending", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        return res.status(403).json({ message: "Organization context required" });
      }
      const pending = getPendingApprovals(orgId);
      res.json(pending);
    } catch (error) {
      logger.child("routes").error("Pending approvals error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch pending approvals" });
    }
  });

  const reviewSchema = z.object({
    reviewerName: z.string().min(1).max(200),
    decision: z.enum(["approved", "rejected"]),
    notes: z.string().max(2000).default(""),
  });

  app.post("/api/prompt-artifact/approvals/:id/review", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const parsed = reviewSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
      }
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        return res.status(403).json({ message: "Organization context required" });
      }
      const approvalId = String(req.params.id);
      const { reviewerName, decision, notes } = parsed.data;
      const result = reviewApproval(approvalId, reviewerName, decision, notes, orgId);
      if (!result) return res.status(404).json({ message: "Approval not found" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Review approval error", { error: String(error) });
      res.status(500).json({ message: "Failed to review approval" });
    }
  });

  const updateLogicSchema = z.object({
    investigationId: z.string().min(1),
    artifactId: z.string().min(1),
    blockId: z.string().min(1),
    newCode: z.string().min(1).max(50000),
  });

  app.post("/api/prompt-artifact/artifacts/update-logic", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const parsed = updateLogicSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
      }
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        return res.status(403).json({ message: "Organization context required" });
      }
      const { investigationId, artifactId, blockId, newCode } = parsed.data;
      const result = updateArtifactLogic(investigationId, artifactId, blockId, newCode, orgId);
      if (!result) return res.status(404).json({ message: "Artifact or logic block not found" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Update logic error", { error: String(error) });
      res.status(500).json({ message: "Failed to update artifact logic" });
    }
  });
}
