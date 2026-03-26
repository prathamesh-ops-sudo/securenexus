import type { Express } from "express";
import { getOrgId, logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireOrgId, requirePermission, resolveOrgContext } from "../../rbac";
import { bodySchemas, validateBody, validatePathId } from "../../request-validator";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";

export function registerPlaybooksCrudRoutes(app: Express): void {
  // Playbooks (Phase 13 - SOAR-Lite)
  app.get("/api/playbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      res.json(await storage.getPlaybooks(orgId));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbooks" });
    }
  });

  app.get("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb || !orgId || pb.orgId !== orgId) {
        return res.status(404).json({ message: "Playbook not found" });
      }
      res.json(pb);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbook" });
    }
  });

  app.post(
    "/api/playbooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    enforcePlanLimit("playbooks"),
    validateBody(bodySchemas.playbookCreate),
    async (req, res) => {
      try {
        const { name, description, trigger, conditions, actions, status } = (req as any).validatedBody;
        const playbook = await storage.createPlaybook({
          name,
          description,
          trigger,
          conditions,
          actions,
          status: status || "draft",
          createdBy: (req as any).user?.id,
          orgId: (req as any).orgId,
        });
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "playbook_created",
          resourceType: "playbook",
          resourceId: playbook.id,
          details: { name, trigger },
        });
        // playbooks is a resource-count metric — enforcement queries active count directly
        res.status(201).json(playbook);
      } catch (error) {
        res.status(500).json({ message: "Failed to create playbook" });
      }
    },
  );

  app.patch(
    "/api/playbooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const existing = await storage.getPlaybook(p(req.params.id));
        if (!existing || !orgId || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }
        const allowedFields = ["name", "description", "trigger", "conditions", "actions", "status", "enabled"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }
        updates.updatedAt = new Date();
        const updated = await storage.updatePlaybook(p(req.params.id), updates);
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update playbook" });
      }
    },
  );

  app.delete(
    "/api/playbooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requirePermission("incidents", "admin"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const existing = await storage.getPlaybook(p(req.params.id));
        if (!existing || !orgId || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }
        const deleted = await storage.deletePlaybook(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Playbook not found" });
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "playbook_deleted",
          resourceType: "playbook",
          resourceId: p(req.params.id),
        });
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete playbook" });
      }
    },
  );
}
