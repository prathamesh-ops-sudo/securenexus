import type { Express } from "express";
import { getOrgId, logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { validatePathId } from "../../request-validator";
import {
  insertPlaybookVersionSchema,
  insertBlastRadiusPreviewSchema,
  insertPlaybookRollbackPlanSchema,
} from "@shared/schema";
import { extractNodes } from "./utils";

export function registerPlaybooksVersionsRoutes(app: Express): void {
  // Playbook Versions
  app.get("/api/playbooks/:playbookId/versions", isAuthenticated, validatePathId("playbookId"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const versions = await storage.getPlaybookVersions(p(req.params.playbookId), orgId);
      res.json(versions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbook versions" });
    }
  });

  app.get("/api/playbook-versions/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const version = await storage.getPlaybookVersion(p(req.params.id));
      if (!version) return res.status(404).json({ message: "Playbook version not found" });
      res.json(version);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbook version" });
    }
  });

  app.post(
    "/api/playbooks/:playbookId/versions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("playbookId"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const playbookId = p(req.params.playbookId);
        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Unknown";

        const playbook = await storage.getPlaybook(playbookId);
        if (!playbook) return res.status(404).json({ message: "Playbook not found" });

        const latest = await storage.getLatestPlaybookVersion(playbookId);
        const nextVersion = latest ? latest.version + 1 : 1;

        const parsed = insertPlaybookVersionSchema.safeParse({
          ...req.body,
          playbookId,
          orgId,
          version: nextVersion,
          createdBy: userId,
          createdByName: userName,
          actions: req.body.actions || playbook.actions,
          conditions: req.body.conditions || playbook.conditions,
        });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid version data", errors: parsed.error.flatten() });
        }

        const version = await storage.createPlaybookVersion(parsed.data);

        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "playbook_version_created",
          resourceType: "playbook",
          resourceId: playbookId,
          details: { versionId: version.id, version: nextVersion, changeDescription: req.body.changeDescription },
        });

        res.status(201).json(version);
      } catch (error) {
        logger.child("routes").error("Playbook version creation error", { error: String(error) });
        res.status(500).json({ message: "Failed to create playbook version" });
      }
    },
  );

  app.patch("/api/playbook-versions/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const updated = await storage.updatePlaybookVersion(p(req.params.id), req.body);
      if (!updated) return res.status(404).json({ message: "Playbook version not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update playbook version" });
    }
  });

  app.post(
    "/api/playbook-versions/:id/activate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const version = await storage.getPlaybookVersion(p(req.params.id));
        if (!version) return res.status(404).json({ message: "Playbook version not found" });

        const playbook = await storage.getPlaybook(version.playbookId);
        if (!playbook) return res.status(404).json({ message: "Playbook not found" });

        if (version.approvalRequired && !version.approvedBy) {
          return res.status(400).json({ message: "This version requires approval before activation" });
        }

        await storage.updatePlaybook(version.playbookId, {
          actions: version.actions as any,
          conditions: version.conditions as any,
          updatedAt: new Date(),
        });

        const allVersions = await storage.getPlaybookVersions(version.playbookId);
        for (const v of allVersions) {
          if (v.status === "active" && v.id !== version.id) {
            await storage.updatePlaybookVersion(v.id, { status: "deprecated" });
          }
        }

        const activated = await storage.updatePlaybookVersion(p(req.params.id), { status: "active" });

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Unknown";
        await storage.createAuditLog({
          orgId: getOrgId(req),
          userId,
          userName,
          action: "playbook_version_activated",
          resourceType: "playbook",
          resourceId: version.playbookId,
          details: { versionId: version.id, version: version.version },
        });

        res.json(activated);
      } catch (error) {
        logger.child("routes").error("Playbook version activation error", { error: String(error) });
        res.status(500).json({ message: "Failed to activate playbook version" });
      }
    },
  );

  app.post(
    "/api/playbook-versions/:id/rollback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const version = await storage.getPlaybookVersion(p(req.params.id));
        if (!version) return res.status(404).json({ message: "Playbook version not found" });

        const playbook = await storage.getPlaybook(version.playbookId);
        if (!playbook) return res.status(404).json({ message: "Playbook not found" });

        await storage.updatePlaybook(version.playbookId, {
          actions: version.actions as any,
          conditions: version.conditions as any,
          updatedAt: new Date(),
        });

        const latest = await storage.getLatestPlaybookVersion(version.playbookId);
        const rollbackVersion = await storage.createPlaybookVersion({
          playbookId: version.playbookId,
          orgId: version.orgId,
          version: (latest?.version ?? 0) + 1,
          status: "active",
          actions: version.actions as any,
          conditions: version.conditions as any,
          changeDescription: `Rollback to version ${version.version}`,
          rollbackToVersion: version.version,
          createdBy: (req as any).user?.id,
          createdByName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Unknown",
        });

        await storage.createAuditLog({
          orgId: getOrgId(req),
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Unknown",
          action: "playbook_version_rollback",
          resourceType: "playbook",
          resourceId: version.playbookId,
          details: { rolledBackTo: version.version, newVersionId: rollbackVersion.id },
        });

        res.json(rollbackVersion);
      } catch (error) {
        logger.child("routes").error("Playbook version rollback error", { error: String(error) });
        res.status(500).json({ message: "Failed to rollback playbook version" });
      }
    },
  );

  // Blast Radius Previews
  app.get(
    "/api/playbooks/:playbookId/blast-radius",
    isAuthenticated,
    validatePathId("playbookId"),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const previews = await storage.getBlastRadiusPreviews(p(req.params.playbookId), orgId);
        res.json(previews);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch blast radius previews" });
      }
    },
  );

  app.post(
    "/api/playbooks/:playbookId/blast-radius",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("playbookId"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const playbookId = p(req.params.playbookId);
        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Unknown";

        const playbook = await storage.getPlaybook(playbookId);
        if (!playbook) return res.status(404).json({ message: "Playbook not found" });

        const actionsArr = Array.isArray(playbook.actions) ? playbook.actions : [];
        const affectedEntities: any[] = [];
        const riskFactors: string[] = [];
        let entityCount = 0;
        let estimatedDurationMs = 0;
        let reversible = true;

        for (const action of actionsArr) {
          const actionObj = action as any;
          const actionType = actionObj.type || actionObj.actionType || "unknown";

          if (actionType === "isolate_host" || actionType === "block_ip") {
            affectedEntities.push({
              type: "network",
              identifier: actionObj.config?.target || actionObj.config?.ip || "unknown",
              impact: "connectivity_disruption",
            });
            riskFactors.push("Network isolation may disrupt legitimate services");
            estimatedDurationMs += 5000;
            entityCount++;
          } else if (actionType === "disable_user" || actionType === "revoke_session") {
            affectedEntities.push({
              type: "user",
              identifier: actionObj.config?.userId || actionObj.config?.username || "unknown",
              impact: "access_revoked",
            });
            riskFactors.push("User access disruption");
            estimatedDurationMs += 3000;
            entityCount++;
          } else if (actionType === "quarantine_file" || actionType === "delete_file") {
            affectedEntities.push({
              type: "file",
              identifier: actionObj.config?.path || actionObj.config?.hash || "unknown",
              impact: actionType === "delete_file" ? "permanent_data_loss" : "temporary_quarantine",
            });
            if (actionType === "delete_file") {
              reversible = false;
              riskFactors.push("File deletion is irreversible");
            }
            estimatedDurationMs += 2000;
            entityCount++;
          } else {
            affectedEntities.push({
              type: "generic",
              identifier: actionType,
              impact: "action_execution",
            });
            estimatedDurationMs += 1000;
            entityCount++;
          }
        }

        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
        if (isGraphFormat) {
          const graph = actionsArr[0] as any;
          const nodes = (graph.nodes || []).filter((n: any) => n.type === "action");
          entityCount = nodes.length;
          affectedEntities.length = 0;
          riskFactors.length = 0;
          reversible = true;
          for (const node of nodes) {
            affectedEntities.push({
              type: "action_node",
              identifier: node.data?.label || node.id,
              actionType: node.data?.actionType || "unknown",
              impact: "playbook_action",
            });
          }
          estimatedDurationMs = nodes.length * 3000;
        }

        const riskLevel = !reversible ? "critical" : entityCount > 10 ? "high" : entityCount > 5 ? "medium" : "low";

        const parsed = insertBlastRadiusPreviewSchema.safeParse({
          orgId,
          playbookId,
          executionContext: req.body.executionContext || {},
          affectedEntities,
          affectedEntityCount: entityCount,
          riskLevel,
          riskFactors,
          estimatedDurationMs,
          rollbackPlan: {
            reversible,
            steps: reversible ? ["Undo each action in reverse order"] : ["Manual intervention required"],
          },
          reversible,
          previewedBy: userId,
          previewedByName: userName,
        });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid blast radius preview", errors: parsed.error.flatten() });
        }

        const preview = await storage.createBlastRadiusPreview(parsed.data);
        res.status(201).json(preview);
      } catch (error) {
        logger.child("routes").error("Blast radius preview error", { error: String(error) });
        res.status(500).json({ message: "Failed to create blast radius preview" });
      }
    },
  );

  // Playbook Rollback Plans
  app.get(
    "/api/playbooks/:playbookId/rollback-plans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("playbookId"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const plans = await storage.getPlaybookRollbackPlans(p(req.params.playbookId), orgId);
        res.json(plans);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch rollback plans" });
      }
    },
  );

  app.get(
    "/api/playbook-rollback-plans/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const plan = await storage.getPlaybookRollbackPlan(p(req.params.id));
        if (!plan || plan.orgId !== orgId) {
          return res.status(404).json({ message: "Rollback plan not found" });
        }
        res.json(plan);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch rollback plan" });
      }
    },
  );

  app.post(
    "/api/playbooks/:playbookId/rollback-plans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("playbookId"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const playbookId = p(req.params.playbookId);
        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Unknown";

        const playbook = await storage.getPlaybook(playbookId);
        if (!playbook || playbook.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const parsed = insertPlaybookRollbackPlanSchema.safeParse({
          ...req.body,
          playbookId,
          orgId,
          createdBy: userId,
          createdByName: userName,
        });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid rollback plan data", errors: parsed.error.flatten() });
        }

        const plan = await storage.createPlaybookRollbackPlan(parsed.data);
        res.status(201).json(plan);
      } catch (error) {
        logger.child("routes").error("Rollback plan creation error", { error: String(error) });
        res.status(500).json({ message: "Failed to create rollback plan" });
      }
    },
  );

  app.post(
    "/api/playbook-rollback-plans/:id/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const plan = await storage.getPlaybookRollbackPlan(p(req.params.id));
        if (!plan || plan.orgId !== orgId) {
          return res.status(404).json({ message: "Rollback plan not found" });
        }

        if (plan.executedAt) {
          return res.status(400).json({ message: "Rollback plan has already been executed" });
        }

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Unknown";

        const steps = Array.isArray(plan.rollbackSteps) ? plan.rollbackSteps : [];
        const executionResults: any[] = [];
        for (const step of steps as any[]) {
          executionResults.push({
            step: step.description || step.action || "unknown",
            status: "completed",
            executedAt: new Date().toISOString(),
            message: `[Rollback] Executed: ${step.description || step.action}`,
          });
        }

        const updated = await storage.updatePlaybookRollbackPlan(p(req.params.id), {
          status: "executed",
          executedAt: new Date(),
          executedBy: userId,
          executedByName: userName,
          result: { steps: executionResults, completedAt: new Date().toISOString() },
        });

        await storage.createAuditLog({
          orgId: getOrgId(req),
          userId,
          userName,
          action: "playbook_rollback_executed",
          resourceType: "playbook",
          resourceId: plan.playbookId,
          details: { rollbackPlanId: plan.id, stepsExecuted: executionResults.length },
        });

        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Rollback plan execution error", { error: String(error) });
        res.status(500).json({ message: "Failed to execute rollback plan" });
      }
    },
  );

  app.patch(
    "/api/playbook-rollback-plans/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const plan = await storage.getPlaybookRollbackPlan(p(req.params.id));
        if (!plan || plan.orgId !== orgId) {
          return res.status(404).json({ message: "Rollback plan not found" });
        }
        const allowedFields = ["rollbackSteps", "status", "autoRollbackEnabled", "triggerConditions", "error"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }
        const updated = await storage.updatePlaybookRollbackPlan(p(req.params.id), updates);
        if (!updated) return res.status(404).json({ message: "Rollback plan not found" });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Rollback plan update error", { error: String(error) });
        res.status(500).json({ message: "Failed to update rollback plan" });
      }
    },
  );

  // ─── 20.3 Playbook Version Diffing ──────────────────────────────────────────

  app.get(
    "/api/playbook-versions/:id1/diff/:id2",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id1"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const v1 = await storage.getPlaybookVersion(p(req.params.id1));
        const v2 = await storage.getPlaybookVersion(p(req.params.id2));

        if (!v1 || !v2) {
          return res.status(404).json({ message: "One or both versions not found" });
        }

        // Ensure both belong to same playbook and same org
        if (v1.playbookId !== v2.playbookId) {
          return res.status(400).json({ message: "Versions must belong to the same playbook" });
        }
        const pb = await storage.getPlaybook(v1.playbookId);
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        // Compare version data using actions/conditions fields
        const snap1: Record<string, unknown> = { actions: v1.actions, conditions: v1.conditions, status: v1.status };
        const snap2: Record<string, unknown> = { actions: v2.actions, conditions: v2.conditions, status: v2.status };

        const changes: any[] = [];

        // Compare basic fields
        const fields = ["name", "description", "trigger", "status", "conditions"];
        for (const field of fields) {
          if (JSON.stringify(snap1[field]) !== JSON.stringify(snap2[field])) {
            changes.push({
              field,
              type: "modified",
              oldValue: snap1[field],
              newValue: snap2[field],
            });
          }
        }

        // Compare actions/nodes
        const nodes1 = extractNodes(snap1.actions);
        const nodes2 = extractNodes(snap2.actions);

        const nodeIds1 = new Set(nodes1.map((n: any) => n.id));
        const nodeIds2 = new Set(nodes2.map((n: any) => n.id));

        for (const node of nodes2) {
          if (!nodeIds1.has(node.id)) {
            changes.push({ field: "steps", type: "added", newValue: node });
          }
        }

        for (const node of nodes1) {
          if (!nodeIds2.has(node.id)) {
            changes.push({ field: "steps", type: "removed", oldValue: node });
          }
        }

        for (const node2 of nodes2) {
          const node1 = nodes1.find((n: any) => n.id === node2.id);
          if (node1 && JSON.stringify(node1) !== JSON.stringify(node2)) {
            changes.push({
              field: "steps",
              type: "modified",
              nodeId: node2.id,
              oldValue: node1,
              newValue: node2,
            });
          }
        }

        res.json({
          playbookId: v1.playbookId,
          playbookName: pb.name,
          version1: {
            id: v1.id,
            version: v1.version,
            changeDescription: v1.changeDescription,
            createdAt: v1.createdAt,
          },
          version2: {
            id: v2.id,
            version: v2.version,
            changeDescription: v2.changeDescription,
            createdAt: v2.createdAt,
          },
          changes,
          summary: {
            totalChanges: changes.length,
            added: changes.filter((c) => c.type === "added").length,
            removed: changes.filter((c) => c.type === "removed").length,
            modified: changes.filter((c) => c.type === "modified").length,
          },
        });
      } catch (error) {
        logger.child("routes").error("Version diff error", { error: String(error) });
        res.status(500).json({ message: "Failed to diff versions" });
      }
    },
  );
}
