import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireOrgId, requirePermission, resolveOrgContext, requireMinRole } from "../rbac";
import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../request-validator";
import { dispatchAction, type ActionContext } from "../action-dispatcher";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { canRollback, createRollbackRecord } from "../rollback-engine";
import {
  insertPlaybookVersionSchema,
  insertBlastRadiusPreviewSchema,
  insertPlaybookSimulationSchema,
  insertPlaybookRollbackPlanSchema,
} from "@shared/schema";

export function registerPlaybooksRoutes(app: Express): void {
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

  app.post("/api/playbooks/:id/execute", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb || !orgId || pb.orgId !== orgId) {
        return res.status(404).json({ message: "Playbook not found" });
      }
      const startTime = Date.now();
      const user = (req as any).user;
      const isDryRun = req.body.dryRun === true;
      const context: ActionContext = {
        orgId: user?.orgId || pb.orgId || undefined,
        incidentId: req.body.resourceId,
        alertId: req.body.alertId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Manual",
        storage,
      };

      const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
      const executedActions: any[] = [];

      const execution = await storage.createPlaybookExecution({
        playbookId: pb.id,
        triggeredBy: context.userName,
        triggerEvent: "manual",
        resourceType: req.body.resourceType,
        resourceId: req.body.resourceId,
        status: "running",
        dryRun: isDryRun,
        actionsExecuted: [],
        result: {},
      });
      const executionId = execution.id;

      const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
      let pausedAtApproval = false;

      if (isGraphFormat) {
        const graph = actionsArr[0] as any;
        const nodes = graph.nodes || [];
        const edges = graph.edges || [];

        const adjacency: Record<string, string[]> = {};
        for (const edge of edges) {
          if (!adjacency[edge.source]) adjacency[edge.source] = [];
          adjacency[edge.source].push(edge.target);
        }

        const targetNodes = new Set(edges.map((e: any) => e.target));
        const startNodes = nodes.filter((n: any) => !targetNodes.has(n.id) || n.type === "trigger");

        const visited = new Set<string>();
        const queue = startNodes.map((n: any) => n.id);
        let execCount = 0;

        while (queue.length > 0 && execCount < 50) {
          const nodeId = queue.shift()!;
          if (visited.has(nodeId)) continue;
          visited.add(nodeId);

          const node = nodes.find((n: any) => n.id === nodeId);
          if (!node) continue;

          if (node.type === "approval") {
            const approval = await storage.createPlaybookApproval({
              executionId: executionId,
              playbookId: pb.id,
              nodeId: node.id,
              status: "pending",
              requestedBy: context.userName,
              approverRole: node.data?.config?.approverRole || "admin",
              approvalMessage: node.data?.config?.message || node.data?.label || "Approval required",
            });
            await storage.updatePlaybookExecution(executionId, {
              status: "awaiting_approval",
              pausedAtNodeId: node.id,
              actionsExecuted: executedActions,
              executionTimeMs: Date.now() - startTime,
              result: { totalActions: executedActions.length, approvalId: approval.id, pausedAt: node.id },
            });
            pausedAtApproval = true;
            break;
          }

          if (node.type === "action" && node.data?.actionType) {
            if (isDryRun) {
              executedActions.push({
                nodeId,
                actionType: node.data.actionType,
                status: "simulated",
                message: `[Dry Run] Would execute: ${node.data.label}`,
                executedAt: new Date().toISOString(),
              });
            } else {
              const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
              executedActions.push({ nodeId, ...result });
            }
            execCount++;
          } else if (node.type === "condition") {
            const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
            for (const edge of trueEdges) {
              queue.push(edge.target);
            }
            executedActions.push({
              nodeId,
              actionType: "condition",
              status: "completed",
              message: `Evaluated condition: ${node.data?.label || "check"}`,
              executedAt: new Date().toISOString(),
            });
            execCount++;
            continue;
          }

          const children = adjacency[nodeId] || [];
          for (const child of children) {
            queue.push(child);
          }
        }
      } else {
        for (const action of actionsArr) {
          const actionObj = action as any;
          const actionType = actionObj.type || actionObj.actionType || "unknown";
          const config =
            typeof actionObj.config === "string"
              ? (() => {
                  try {
                    return JSON.parse(actionObj.config);
                  } catch {
                    return { raw: actionObj.config };
                  }
                })()
              : actionObj.config || {};
          if (isDryRun) {
            executedActions.push({
              actionType,
              status: "simulated",
              message: `[Dry Run] Would execute: ${actionType}`,
              executedAt: new Date().toISOString(),
            });
          } else {
            const result = await dispatchAction(actionType, config, context);
            executedActions.push(result);
          }
        }
      }

      if (!pausedAtApproval) {
        await storage.updatePlaybookExecution(executionId, {
          status: "completed",
          actionsExecuted: executedActions,
          result: {
            totalActions: executedActions.length,
            completedActions: executedActions.filter((a: any) => a.status === "completed" || a.status === "simulated")
              .length,
          },
          executionTimeMs: Date.now() - startTime,
        });
      }

      await storage.updatePlaybook(pb.id, {
        lastTriggeredAt: new Date(),
        triggerCount: (pb.triggerCount || 0) + 1,
      } as any);
      await storage.createAuditLog({
        userId: user?.id,
        userName: context.userName,
        action: "playbook_executed",
        resourceType: "playbook",
        resourceId: pb.id,
        details: {
          name: pb.name,
          trigger: "manual",
          actionsCount: executedActions.length,
          dryRun: isDryRun,
          paused: pausedAtApproval,
        },
      });
      const updatedExecution = await storage.getPlaybookExecution(executionId);
      res.json(updatedExecution || execution);
    } catch (error) {
      logger.child("routes").error("Playbook execution error", { error: String(error) });
      res.status(500).json({ message: "Failed to execute playbook" });
    }
  });

  app.get(
    "/api/playbook-executions",
    isAuthenticated,
    validateQuery(querySchemas.playbookExecutions),
    async (req, res) => {
      try {
        const { playbookId, limit } = (req as any).validatedQuery;
        res.json(await storage.getPlaybookExecutions(playbookId, limit));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch executions" });
      }
    },
  );

  app.get("/api/playbook-approvals", isAuthenticated, validateQuery(querySchemas.approvalStatus), async (req, res) => {
    try {
      const { status } = (req as any).validatedQuery;
      const approvals = await storage.getPlaybookApprovals(status);
      res.json(approvals);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbook approvals" });
    }
  });

  app.post(
    "/api/playbook-approvals/:id/decide",
    isAuthenticated,
    validatePathId("id"),
    validateBody(bodySchemas.approvalDecision),
    async (req, res) => {
      try {
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const { decision, note } = (req as any).validatedBody;

        const approval = await storage.getPlaybookApproval(p(req.params.id));
        if (!approval) return res.status(404).json({ message: "Approval not found" });
        if (approval.status !== "pending") {
          return res.status(400).json({ message: `Approval already ${approval.status}` });
        }

        // Validate linked resources exist
        const execution = await storage.getPlaybookExecution(approval.executionId);
        if (!execution) return res.status(404).json({ message: "Linked execution not found" });
        const pb = await storage.getPlaybook(execution.playbookId);
        if (!pb) return res.status(404).json({ message: "Linked playbook not found" });

        const updatedApproval = await storage.updatePlaybookApproval(approval.id, {
          status: decision,
          decidedBy: userName,
          decisionNote: note || null,
          decidedAt: new Date(),
        });

        if (decision === "approved") {
          if (execution.status === "awaiting_approval") {
            const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
            const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
            if (isGraphFormat) {
              const graph = actionsArr[0] as any;
              const nodes = graph.nodes || [];
              const edges = graph.edges || [];
              const adjacency: Record<string, string[]> = {};
              for (const edge of edges) {
                if (!adjacency[edge.source]) adjacency[edge.source] = [];
                adjacency[edge.source].push(edge.target);
              }
              const pausedNodeId = execution.pausedAtNodeId;
              const resumeFrom = pausedNodeId ? adjacency[pausedNodeId] || [] : [];
              const existingActions = Array.isArray(execution.actionsExecuted)
                ? (execution.actionsExecuted as any[])
                : [];
              const visited = new Set<string>(existingActions.map((a: any) => a.nodeId).filter(Boolean));
              if (pausedNodeId) visited.add(pausedNodeId);
              const queue = [...resumeFrom];
              const newActions: any[] = [];
              let execCount = 0;
              const isDryRun = execution.dryRun === true;
              const context: ActionContext = {
                orgId: user?.orgId || pb.orgId || undefined,
                incidentId: execution.resourceId || undefined,
                userId: user?.id,
                userName,
                storage,
              };
              while (queue.length > 0 && execCount < 50) {
                const nodeId = queue.shift()!;
                if (visited.has(nodeId)) continue;
                visited.add(nodeId);
                const node = nodes.find((n: any) => n.id === nodeId);
                if (!node) continue;
                if (node.type === "action" && node.data?.actionType) {
                  if (isDryRun) {
                    newActions.push({
                      nodeId,
                      actionType: node.data.actionType,
                      status: "simulated",
                      message: `[Dry Run] Would execute: ${node.data.label}`,
                      executedAt: new Date().toISOString(),
                    });
                  } else {
                    const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
                    newActions.push({ nodeId, ...result });
                  }
                  execCount++;
                } else if (node.type === "condition") {
                  const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
                  for (const edge of trueEdges) {
                    queue.push(edge.target);
                  }
                  newActions.push({
                    nodeId,
                    actionType: "condition",
                    status: "completed",
                    message: `Evaluated condition: ${node.data?.label || "check"}`,
                    executedAt: new Date().toISOString(),
                  });
                  execCount++;
                  continue;
                }
                const children = adjacency[nodeId] || [];
                for (const child of children) {
                  queue.push(child);
                }
              }
              const mergedActions = [...existingActions, ...newActions];
              await storage.updatePlaybookExecution(execution.id, {
                status: "completed",
                pausedAtNodeId: null,
                actionsExecuted: mergedActions,
                result: {
                  totalActions: mergedActions.length,
                  completedActions: mergedActions.filter(
                    (a: any) => a.status === "completed" || a.status === "simulated",
                  ).length,
                },
              });
            }
          }
        } else {
          await storage.updatePlaybookExecution(approval.executionId, { status: "rejected" });
        }

        await storage.createAuditLog({
          userId: user?.id,
          userName,
          action: `playbook_approval_${decision}`,
          resourceType: "playbook_approval",
          resourceId: approval.id,
          details: { executionId: approval.executionId, playbookId: approval.playbookId, decision, note },
        });

        res.json(updatedApproval);
      } catch (error) {
        logger.child("routes").error("Approval decision error", { error: String(error) });
        res.status(500).json({ message: "Failed to process approval decision" });
      }
    },
  );

  app.post("/api/playbook-executions/:id/resume", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const execution = await storage.getPlaybookExecution(p(req.params.id));
      if (!execution) return res.status(404).json({ message: "Execution not found" });
      if (execution.status !== "awaiting_approval") {
        return res.status(400).json({ message: `Execution is not paused, current status: ${execution.status}` });
      }

      const pb = await storage.getPlaybook(execution.playbookId);
      if (!pb) return res.status(404).json({ message: "Playbook not found" });

      const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
      const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
      if (!isGraphFormat) {
        return res.status(400).json({ message: "Playbook is not in graph format, cannot resume" });
      }

      const graph = actionsArr[0] as any;
      const nodes = graph.nodes || [];
      const edges = graph.edges || [];
      const adjacency: Record<string, string[]> = {};
      for (const edge of edges) {
        if (!adjacency[edge.source]) adjacency[edge.source] = [];
        adjacency[edge.source].push(edge.target);
      }

      const pausedNodeId = execution.pausedAtNodeId;
      const resumeFrom = pausedNodeId ? adjacency[pausedNodeId] || [] : [];
      const existingActions = Array.isArray(execution.actionsExecuted) ? (execution.actionsExecuted as any[]) : [];
      const visited = new Set<string>(existingActions.map((a: any) => a.nodeId).filter(Boolean));
      if (pausedNodeId) visited.add(pausedNodeId);
      const queue = [...resumeFrom];
      const newActions: any[] = [];
      let execCount = 0;
      const isDryRun = execution.dryRun === true;
      const context: ActionContext = {
        orgId: user?.orgId || pb.orgId || undefined,
        incidentId: execution.resourceId || undefined,
        userId: user?.id,
        userName,
        storage,
      };

      while (queue.length > 0 && execCount < 50) {
        const nodeId = queue.shift()!;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);
        const node = nodes.find((n: any) => n.id === nodeId);
        if (!node) continue;
        if (node.type === "action" && node.data?.actionType) {
          if (isDryRun) {
            newActions.push({
              nodeId,
              actionType: node.data.actionType,
              status: "simulated",
              message: `[Dry Run] Would execute: ${node.data.label}`,
              executedAt: new Date().toISOString(),
            });
          } else {
            const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
            newActions.push({ nodeId, ...result });
          }
          execCount++;
        } else if (node.type === "condition") {
          const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
          for (const edge of trueEdges) {
            queue.push(edge.target);
          }
          newActions.push({
            nodeId,
            actionType: "condition",
            status: "completed",
            message: `Evaluated condition: ${node.data?.label || "check"}`,
            executedAt: new Date().toISOString(),
          });
          execCount++;
          continue;
        }
        const children = adjacency[nodeId] || [];
        for (const child of children) {
          queue.push(child);
        }
      }

      const mergedActions = [...existingActions, ...newActions];
      const updated = await storage.updatePlaybookExecution(execution.id, {
        status: "completed",
        pausedAtNodeId: null,
        actionsExecuted: mergedActions,
        result: {
          totalActions: mergedActions.length,
          completedActions: mergedActions.filter((a: any) => a.status === "completed" || a.status === "simulated")
            .length,
        },
      });

      await storage.createAuditLog({
        userId: user?.id,
        userName,
        action: "playbook_execution_resumed",
        resourceType: "playbook_execution",
        resourceId: execution.id,
        details: { playbookId: execution.playbookId, newActionsCount: newActions.length },
      });

      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Resume execution error", { error: String(error) });
      res.status(500).json({ message: "Failed to resume execution" });
    }
  });

  app.post("/api/playbook-executions/:id/rollback", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const execution = await storage.getPlaybookExecution(p(req.params.id));
      if (!execution) return res.status(404).json({ message: "Execution not found" });

      const actionsExecuted = Array.isArray(execution.actionsExecuted) ? (execution.actionsExecuted as any[]) : [];
      const rollbackEligible = actionsExecuted.filter((a: any) => canRollback(a.actionType));

      if (rollbackEligible.length === 0) {
        return res.json({ message: "No rollback-eligible actions found", rollbacks: [] });
      }

      const orgId = getOrgId(req);
      const rollbacks = [];
      for (const action of rollbackEligible) {
        const target =
          action.details?.target || action.details?.hostname || action.details?.ip || action.nodeId || "unknown";
        const rollback = await createRollbackRecord(orgId, execution.id, action.actionType, target);
        rollbacks.push(rollback);
      }

      await storage.createAuditLog({
        userId: user?.id,
        userName,
        action: "playbook_execution_rollback",
        resourceType: "playbook_execution",
        resourceId: execution.id,
        details: { rollbackCount: rollbacks.length, actionTypes: rollbackEligible.map((a: any) => a.actionType) },
      });

      res.json({ message: `Created ${rollbacks.length} rollback records`, rollbacks });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      logger.child("routes").error("Rollback creation error", { error: String(error) });
      res.status(500).json({ message: "Failed to create rollback records" });
    }
  });

  // ==========================================
  // 8.3 — Playbook Versions
  // ==========================================

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

  // ==========================================
  // 8.3 — Blast Radius Previews
  // ==========================================

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

  // ==========================================
  // 8.3 — Playbook Simulations
  // ==========================================

  app.get(
    "/api/playbooks/:playbookId/simulations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("playbookId"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const simulations = await storage.getPlaybookSimulations(p(req.params.playbookId), orgId);
        res.json(simulations);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch playbook simulations" });
      }
    },
  );

  app.get(
    "/api/playbook-simulations/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const simulation = await storage.getPlaybookSimulation(p(req.params.id));
        if (!simulation || simulation.orgId !== orgId) {
          return res.status(404).json({ message: "Simulation not found" });
        }
        res.json(simulation);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch simulation" });
      }
    },
  );

  app.patch(
    "/api/playbook-simulations/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const simulation = await storage.getPlaybookSimulation(p(req.params.id));
        if (!simulation || simulation.orgId !== orgId) {
          return res.status(404).json({ message: "Simulation not found" });
        }
        const allowedFields = [
          "status",
          "simulatedActions",
          "impactAnalysis",
          "predictedOutcome",
          "riskScore",
          "warnings",
          "durationMs",
          "completedAt",
        ];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }
        const updated = await storage.updatePlaybookSimulation(p(req.params.id), updates);
        if (!updated) return res.status(404).json({ message: "Simulation not found" });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Simulation update error", { error: String(error) });
        res.status(500).json({ message: "Failed to update simulation" });
      }
    },
  );

  app.post(
    "/api/playbooks/:playbookId/simulate",
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
        if (!playbook) return res.status(404).json({ message: "Playbook not found" });

        const simulation = await storage.createPlaybookSimulation({
          playbookId,
          orgId,
          status: "running",
          simulatedBy: userId,
          simulatedByName: userName,
        });

        const actionsArr = Array.isArray(playbook.actions) ? playbook.actions : [];
        const simulatedActions: any[] = [];
        const startTime = Date.now();

        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
        if (isGraphFormat) {
          const graph = actionsArr[0] as any;
          const nodes = graph.nodes || [];
          for (const node of nodes) {
            if (node.type === "action") {
              simulatedActions.push({
                nodeId: node.id,
                actionType: node.data?.actionType || "unknown",
                label: node.data?.label || node.id,
                status: "simulated",
                wouldExecute: true,
                simulatedResult: {
                  message: `[Simulation] Would execute: ${node.data?.label || node.data?.actionType}`,
                },
                simulatedAt: new Date().toISOString(),
              });
            } else if (node.type === "condition") {
              simulatedActions.push({
                nodeId: node.id,
                actionType: "condition",
                label: node.data?.label || "Condition check",
                status: "simulated",
                evaluatedTo: true,
                simulatedAt: new Date().toISOString(),
              });
            } else if (node.type === "approval") {
              simulatedActions.push({
                nodeId: node.id,
                actionType: "approval_gate",
                label: node.data?.label || "Approval required",
                status: "simulated",
                wouldPause: true,
                simulatedAt: new Date().toISOString(),
              });
            }
          }
        } else {
          for (const action of actionsArr) {
            const actionObj = action as any;
            simulatedActions.push({
              actionType: actionObj.type || actionObj.actionType || "unknown",
              status: "simulated",
              wouldExecute: true,
              simulatedResult: { message: `[Simulation] Would execute: ${actionObj.type || actionObj.actionType}` },
              simulatedAt: new Date().toISOString(),
            });
          }
        }

        const impactAnalysis = {
          totalActions: simulatedActions.length,
          approvalGates: simulatedActions.filter((a) => a.actionType === "approval_gate").length,
          conditions: simulatedActions.filter((a) => a.actionType === "condition").length,
          executionActions: simulatedActions.filter((a) => a.wouldExecute).length,
          estimatedDurationMs: simulatedActions.length * 2000,
        };

        const updated = await storage.updatePlaybookSimulation(simulation.id, {
          status: "completed",
          simulatedActions,
          impactAnalysis,
          durationMs: Date.now() - startTime,
          completedAt: new Date(),
        });

        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "playbook_simulation_completed",
          resourceType: "playbook",
          resourceId: playbookId,
          details: { simulationId: simulation.id, actionsSimulated: simulatedActions.length },
        });

        res.status(201).json(updated || simulation);
      } catch (error) {
        logger.child("routes").error("Playbook simulation error", { error: String(error) });
        res.status(500).json({ message: "Failed to run playbook simulation" });
      }
    },
  );

  // ==========================================
  // 8.3 — Playbook Rollback Plans
  // ==========================================

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

  // ─── 20.2 Playbook Execution Monitoring Dashboard ───────────────────────────

  app.get(
    "/api/playbook-executions/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const allExecs = await storage.getPlaybookExecutions(undefined, 200);
        // Filter to org's playbooks
        const orgPlaybooks = await storage.getPlaybooks(orgId);
        const orgPbIds = new Set(orgPlaybooks.map((p: any) => p.id));
        const orgExecs = allExecs.filter((e: any) => orgPbIds.has(e.playbookId));

        const running = orgExecs.filter((e: any) => e.status === "running");
        const awaitingApproval = orgExecs.filter((e: any) => e.status === "awaiting_approval");
        const failed = orgExecs.filter((e: any) => e.status === "failed");
        const completed = orgExecs.filter((e: any) => e.status === "completed");
        const recent = orgExecs.slice(0, 20);

        // Compute stats
        const avgExecutionTime =
          completed.length > 0
            ? Math.round(
                completed.reduce((sum: number, e: any) => sum + (e.executionTimeMs || 0), 0) / completed.length,
              )
            : 0;
        const successRate = orgExecs.length > 0 ? Math.round((completed.length / orgExecs.length) * 100) : 0;

        // Build per-playbook stats
        const perPlaybook: Record<string, any> = {};
        for (const exec of orgExecs) {
          const pbId = exec.playbookId;
          if (!perPlaybook[pbId]) {
            const pb = orgPlaybooks.find((p: any) => p.id === pbId);
            perPlaybook[pbId] = {
              playbookId: pbId,
              playbookName: pb?.name || "Unknown",
              totalExecutions: 0,
              completed: 0,
              failed: 0,
              running: 0,
              awaitingApproval: 0,
              avgTimeMs: 0,
              totalTimeMs: 0,
            };
          }
          perPlaybook[pbId].totalExecutions++;
          if (exec.status === "completed") {
            perPlaybook[pbId].completed++;
            perPlaybook[pbId].totalTimeMs += exec.executionTimeMs || 0;
          }
          if (exec.status === "failed") perPlaybook[pbId].failed++;
          if (exec.status === "running") perPlaybook[pbId].running++;
          if (exec.status === "awaiting_approval") perPlaybook[pbId].awaitingApproval++;
        }
        for (const stats of Object.values(perPlaybook)) {
          (stats as any).avgTimeMs =
            (stats as any).completed > 0 ? Math.round((stats as any).totalTimeMs / (stats as any).completed) : 0;
        }

        res.json({
          summary: {
            total: orgExecs.length,
            running: running.length,
            awaitingApproval: awaitingApproval.length,
            failed: failed.length,
            completed: completed.length,
            avgExecutionTimeMs: avgExecutionTime,
            successRate,
          },
          activeExecutions: [...running, ...awaitingApproval].map((e: any) => ({
            id: e.id,
            playbookId: e.playbookId,
            playbookName: orgPlaybooks.find((p: any) => p.id === e.playbookId)?.name || "Unknown",
            status: e.status,
            triggeredBy: e.triggeredBy,
            triggerEvent: e.triggerEvent,
            startedAt: e.createdAt,
            executionTimeMs: e.executionTimeMs,
            currentStep: e.pausedAtNodeId || null,
            actionsExecuted: Array.isArray(e.actionsExecuted) ? e.actionsExecuted.length : 0,
            dryRun: e.dryRun || false,
          })),
          recentExecutions: recent.map((e: any) => ({
            id: e.id,
            playbookId: e.playbookId,
            playbookName: orgPlaybooks.find((p: any) => p.id === e.playbookId)?.name || "Unknown",
            status: e.status,
            triggeredBy: e.triggeredBy,
            triggerEvent: e.triggerEvent,
            startedAt: e.createdAt,
            executionTimeMs: e.executionTimeMs,
            dryRun: e.dryRun || false,
            actionsCount: Array.isArray(e.actionsExecuted) ? e.actionsExecuted.length : 0,
          })),
          perPlaybook: Object.values(perPlaybook),
          failedExecutions: failed.slice(0, 10).map((e: any) => ({
            id: e.id,
            playbookId: e.playbookId,
            playbookName: orgPlaybooks.find((p: any) => p.id === e.playbookId)?.name || "Unknown",
            triggeredBy: e.triggeredBy,
            failedAt: e.updatedAt || e.createdAt,
            error: (e.result as any)?.error || "Unknown error",
          })),
        });
      } catch (error) {
        logger.child("routes").error("Execution dashboard error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch execution dashboard" });
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

  // ─── 20.4 Playbook Dry-Run / Simulation Mode (enhanced) ────────────────────

  app.post(
    "/api/playbooks/:id/simulate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const { parameters, scenarioName } = req.body;

        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const simulatedActions: any[] = [];
        const startTime = Date.now();

        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;

        if (isGraphFormat) {
          const graph = actionsArr[0] as any;
          const nodes = graph.nodes || [];
          const edges = graph.edges || [];
          const adjacency: Record<string, string[]> = {};
          for (const edge of edges) {
            if (!adjacency[edge.source]) adjacency[edge.source] = [];
            adjacency[edge.source].push(edge.target);
          }
          const targetNodes = new Set(edges.map((e: any) => e.target));
          const startNodes = nodes.filter((n: any) => !targetNodes.has(n.id) || n.type === "trigger");
          const visited = new Set<string>();
          const queue = startNodes.map((n: any) => n.id);
          let stepNum = 0;

          while (queue.length > 0 && stepNum < 50) {
            const nodeId = queue.shift()!;
            if (visited.has(nodeId)) continue;
            visited.add(nodeId);
            const node = nodes.find((n: any) => n.id === nodeId);
            if (!node) continue;
            stepNum++;

            const simResult: any = {
              step: stepNum,
              nodeId: node.id,
              nodeType: node.type,
              label: node.data?.label || node.type,
              actionType: node.data?.actionType || node.type,
              status: "simulated",
              wouldExecute: node.type === "action",
              wouldBlock: node.type === "approval",
              estimatedDurationMs: Math.floor(Math.random() * 5000) + 500,
              timestamp: new Date(startTime + stepNum * 1000).toISOString(),
              impact: [],
            };

            // Estimate impact
            if (node.type === "action") {
              const actionType = node.data?.actionType || "";
              if (
                [
                  "isolate_host",
                  "block_ip",
                  "block_domain",
                  "disable_user",
                  "kill_process",
                  "quarantine_file",
                ].includes(actionType)
              ) {
                simResult.impact.push({
                  type: "destructive",
                  description: `Would perform: ${node.data?.label}`,
                  reversible: true,
                });
                simResult.riskLevel = "high";
              } else if (["notify_slack", "notify_teams", "notify_email", "notify_webhook"].includes(actionType)) {
                simResult.impact.push({
                  type: "notification",
                  description: `Would send notification: ${node.data?.label}`,
                  reversible: false,
                });
                simResult.riskLevel = "low";
              } else {
                simResult.impact.push({
                  type: "informational",
                  description: `Would execute: ${node.data?.label}`,
                  reversible: true,
                });
                simResult.riskLevel = "medium";
              }
            }

            simulatedActions.push(simResult);
            const children = adjacency[nodeId] || [];
            for (const child of children) {
              queue.push(child);
            }
          }
        } else {
          let stepNum = 0;
          for (const action of actionsArr) {
            stepNum++;
            const actionObj = action as any;
            const actionType = actionObj.type || actionObj.actionType || "unknown";
            simulatedActions.push({
              step: stepNum,
              actionType,
              label: actionObj.label || actionType,
              status: "simulated",
              wouldExecute: true,
              estimatedDurationMs: Math.floor(Math.random() * 5000) + 500,
              timestamp: new Date(startTime + stepNum * 1000).toISOString(),
              riskLevel: "medium",
              impact: [{ type: "informational", description: `Would execute: ${actionType}` }],
            });
          }
        }

        const totalDuration = simulatedActions.reduce((sum: number, a: any) => sum + (a.estimatedDurationMs || 0), 0);
        const highRiskSteps = simulatedActions.filter((a: any) => a.riskLevel === "high");
        const approvalGates = simulatedActions.filter((a: any) => a.wouldBlock);

        const simulation = await storage.createPlaybookSimulation({
          playbookId: pb.id,
          orgId,
          simulatedActions: simulatedActions as any,
          impactAnalysis: {
            totalSteps: simulatedActions.length,
            estimatedDurationMs: totalDuration,
            highRiskSteps: highRiskSteps.length,
            approvalGates: approvalGates.length,
            scenarioName: scenarioName || "Manual simulation",
          } as any,
          predictedOutcome: `${simulatedActions.length} steps, ${highRiskSteps.length} high-risk`,
          status: "completed",
          simulatedBy: user?.id,
          simulatedByName: userName,
          durationMs: Date.now() - startTime,
        });

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "playbook_simulated",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { simulationId: simulation.id, stepsCount: simulatedActions.length, scenarioName },
        });

        res.json({
          simulationId: simulation.id,
          playbookName: pb.name,
          steps: simulatedActions,
          summary: {
            totalSteps: simulatedActions.length,
            estimatedDurationMs: totalDuration,
            highRiskSteps: highRiskSteps.length,
            approvalGates: approvalGates.length,
            destructiveActions: simulatedActions.filter((a: any) =>
              a.impact?.some((i: any) => i.type === "destructive"),
            ).length,
          },
        });
      } catch (error) {
        logger.child("routes").error("Playbook simulation error", { error: String(error) });
        res.status(500).json({ message: "Failed to simulate playbook" });
      }
    },
  );

  // ─── 20.5 Playbook Step Timeout Handling ────────────────────────────────────

  const stepTimeoutDefaults: Record<string, number> = {
    action: 30000,
    condition: 5000,
    approval: 0, // approvals don't timeout by default
    trigger: 5000,
    notification: 10000,
  };

  const FALLBACK_ACTIONS = ["skip", "retry", "abort", "notify"] as const;

  app.get(
    "/api/playbooks/:id/step-timeouts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const nodes = extractNodes(actionsArr);
        const stepConfigs = nodes.map((node: any) => {
          const config = node.data?.config || {};
          return {
            nodeId: node.id,
            label: node.data?.label || node.type,
            type: node.type,
            timeoutMs: config.timeoutMs ?? stepTimeoutDefaults[node.type] ?? 30000,
            fallbackAction: config.fallbackAction || "skip",
            maxRetries: config.maxRetries ?? 0,
            retryBackoffMs: config.retryBackoffMs ?? 1000,
          };
        });

        res.json({
          playbookId: pb.id,
          playbookName: pb.name,
          defaults: stepTimeoutDefaults,
          availableFallbacks: FALLBACK_ACTIONS,
          steps: stepConfigs,
        });
      } catch (error) {
        logger.child("routes").error("Step timeouts error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch step timeouts" });
      }
    },
  );

  app.patch(
    "/api/playbooks/:id/step-timeouts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const { steps } = req.body;
        if (!Array.isArray(steps)) {
          return res.status(400).json({ message: "steps must be an array of {nodeId, timeoutMs, fallbackAction}" });
        }

        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;

        if (isGraphFormat) {
          const graph = { ...(actionsArr[0] as any) };
          const nodes = [...(graph.nodes || [])];
          for (const stepUpdate of steps) {
            const idx = nodes.findIndex((n: any) => n.id === stepUpdate.nodeId);
            if (idx >= 0) {
              const node = { ...nodes[idx] };
              const data = { ...node.data, config: { ...(node.data?.config || {}) } };
              if (typeof stepUpdate.timeoutMs === "number") data.config.timeoutMs = stepUpdate.timeoutMs;
              if (stepUpdate.fallbackAction && FALLBACK_ACTIONS.includes(stepUpdate.fallbackAction)) {
                data.config.fallbackAction = stepUpdate.fallbackAction;
              }
              if (typeof stepUpdate.maxRetries === "number") data.config.maxRetries = stepUpdate.maxRetries;
              if (typeof stepUpdate.retryBackoffMs === "number") data.config.retryBackoffMs = stepUpdate.retryBackoffMs;
              node.data = data;
              nodes[idx] = node;
            }
          }
          graph.nodes = nodes;
          await storage.updatePlaybook(pb.id, { actions: [graph] } as any);
        }

        const user = (req as any).user;
        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
          action: "playbook_step_timeouts_updated",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { stepsUpdated: steps.length },
        });

        res.json({ success: true, stepsUpdated: steps.length });
      } catch (error) {
        logger.child("routes").error("Step timeouts update error", { error: String(error) });
        res.status(500).json({ message: "Failed to update step timeouts" });
      }
    },
  );

  // ─── 20.6 Playbook Execution Retry with Backoff ─────────────────────────────

  const retryRegistry = new Map<string, { retries: number; maxRetries: number; backoffMs: number; stepId: string }>();

  app.post(
    "/api/playbook-executions/:id/retry-step",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const execution = await storage.getPlaybookExecution(p(req.params.id));
        if (!execution) {
          return res.status(404).json({ message: "Execution not found" });
        }
        const pb = await storage.getPlaybook(execution.playbookId);
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const { stepId, maxRetries, backoffMs } = req.body;
        if (!stepId) {
          return res.status(400).json({ message: "stepId is required" });
        }

        const retryMax = typeof maxRetries === "number" ? Math.min(maxRetries, 10) : 3;
        const backoff = typeof backoffMs === "number" ? Math.min(backoffMs, 30000) : 1000;
        const key = `${execution.id}:${stepId}`;

        let entry = retryRegistry.get(key);
        if (!entry) {
          entry = { retries: 0, maxRetries: retryMax, backoffMs: backoff, stepId };
          retryRegistry.set(key, entry);
        }

        if (entry.retries >= entry.maxRetries) {
          return res.status(400).json({
            message: `Max retries (${entry.maxRetries}) exhausted for step ${stepId}`,
            retries: entry.retries,
            maxRetries: entry.maxRetries,
          });
        }

        entry.retries++;
        const delay = entry.backoffMs * Math.pow(2, entry.retries - 1);

        // Find the failed action and re-dispatch after delay
        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const nodes = extractNodes(actionsArr);
        const node = nodes.find((n: any) => n.id === stepId);

        if (!node) {
          return res.status(404).json({ message: `Step ${stepId} not found in playbook` });
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const context: ActionContext = {
          orgId,
          incidentId: execution.resourceId || undefined,
          userId: user?.id,
          userName,
          storage,
        };

        // Simulate backoff delay (capped at 5s for API response)
        const actualDelay = Math.min(delay, 5000);
        await new Promise((resolve) => setTimeout(resolve, actualDelay));

        const actionType = node.data?.actionType || node.type;
        const config = node.data?.config || {};
        const result = await dispatchAction(actionType, config, context);

        // Update execution's actionsExecuted with retry result
        const existingActions = Array.isArray(execution.actionsExecuted)
          ? [...(execution.actionsExecuted as any[])]
          : [];
        existingActions.push({
          ...result,
          nodeId: stepId,
          retryAttempt: entry.retries,
          retryDelay: delay,
        });

        const newStatus =
          result.status === "completed" || result.status === "approved" ? "completed" : execution.status;
        await storage.updatePlaybookExecution(execution.id, {
          actionsExecuted: existingActions,
          status: newStatus,
        });

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "playbook_step_retried",
          resourceType: "playbook_execution",
          resourceId: execution.id,
          details: {
            stepId,
            retryAttempt: entry.retries,
            maxRetries: entry.maxRetries,
            backoffDelay: delay,
            result: result.status,
          },
        });

        res.json({
          stepId,
          retryAttempt: entry.retries,
          maxRetries: entry.maxRetries,
          nextBackoffMs: entry.backoffMs * Math.pow(2, entry.retries),
          result,
          executionStatus: newStatus,
        });
      } catch (error) {
        logger.child("routes").error("Step retry error", { error: String(error) });
        res.status(500).json({ message: "Failed to retry step" });
      }
    },
  );

  app.get(
    "/api/playbook-executions/:id/retry-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const execution = await storage.getPlaybookExecution(p(req.params.id));
        if (!execution) {
          return res.status(404).json({ message: "Execution not found" });
        }
        const pb = await storage.getPlaybook(execution.playbookId);
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const retries: any[] = [];
        for (const [key, entry] of Array.from(retryRegistry.entries())) {
          if (key.startsWith(`${execution.id}:`)) {
            retries.push({
              stepId: entry.stepId,
              retries: entry.retries,
              maxRetries: entry.maxRetries,
              backoffMs: entry.backoffMs,
              nextBackoffMs: entry.backoffMs * Math.pow(2, entry.retries),
              exhausted: entry.retries >= entry.maxRetries,
            });
          }
        }

        res.json({ executionId: execution.id, retries });
      } catch (error) {
        logger.child("routes").error("Retry status error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch retry status" });
      }
    },
  );

  // ─── 20.7 Playbook Execution Analytics ──────────────────────────────────────

  app.get(
    "/api/playbook-analytics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const allPlaybooks = await storage.getPlaybooks(orgId);
        const allExecs = await storage.getPlaybookExecutions(undefined, 500);
        const orgPbIds = new Set(allPlaybooks.map((p: any) => p.id));
        const orgExecs = allExecs.filter((e: any) => orgPbIds.has(e.playbookId));

        // Overall metrics
        const completed = orgExecs.filter((e: any) => e.status === "completed");
        const failed = orgExecs.filter((e: any) => e.status === "failed");
        const totalExecutionTime = completed.reduce((sum: number, e: any) => sum + (e.executionTimeMs || 0), 0);
        const avgExecutionTimeMs = completed.length > 0 ? Math.round(totalExecutionTime / completed.length) : 0;
        const successRate = orgExecs.length > 0 ? Math.round((completed.length / orgExecs.length) * 100) : 0;
        const failureRate = orgExecs.length > 0 ? Math.round((failed.length / orgExecs.length) * 100) : 0;

        // Per-playbook analytics
        const perPlaybook: Record<string, any> = {};
        for (const exec of orgExecs) {
          const pbId = exec.playbookId;
          if (!perPlaybook[pbId]) {
            const pb = allPlaybooks.find((p: any) => p.id === pbId);
            perPlaybook[pbId] = {
              playbookId: pbId,
              playbookName: pb?.name || "Unknown",
              totalExecutions: 0,
              completed: 0,
              failed: 0,
              running: 0,
              totalTimeMs: 0,
              avgTimeMs: 0,
              minTimeMs: Infinity,
              maxTimeMs: 0,
              lastTriggeredAt: null,
              triggerCount: pb?.triggerCount || 0,
              failedSteps: {} as Record<string, number>,
            };
          }
          const entry = perPlaybook[pbId];
          entry.totalExecutions++;
          if (exec.status === "completed") {
            entry.completed++;
            const t = exec.executionTimeMs || 0;
            entry.totalTimeMs += t;
            if (t < entry.minTimeMs) entry.minTimeMs = t;
            if (t > entry.maxTimeMs) entry.maxTimeMs = t;
          }
          if (exec.status === "failed") entry.failed++;
          if (exec.status === "running") entry.running++;
          const execDate = exec.createdAt ? new Date(String(exec.createdAt)).toISOString() : null;
          if (!entry.lastTriggeredAt || (execDate && execDate > entry.lastTriggeredAt)) {
            entry.lastTriggeredAt = execDate;
          }

          // Track failed steps
          if (Array.isArray(exec.actionsExecuted)) {
            for (const action of exec.actionsExecuted as any[]) {
              if (action.status === "failed") {
                const stepKey = action.nodeId || action.actionType || "unknown";
                entry.failedSteps[stepKey] = (entry.failedSteps[stepKey] || 0) + 1;
              }
            }
          }
        }

        // Finalize per-playbook stats
        const playbookStats = Object.values(perPlaybook).map((entry: any) => {
          entry.avgTimeMs = entry.completed > 0 ? Math.round(entry.totalTimeMs / entry.completed) : 0;
          if (entry.minTimeMs === Infinity) entry.minTimeMs = 0;
          entry.successRate =
            entry.totalExecutions > 0 ? Math.round((entry.completed / entry.totalExecutions) * 100) : 0;
          entry.failureRate = entry.totalExecutions > 0 ? Math.round((entry.failed / entry.totalExecutions) * 100) : 0;
          // Convert failedSteps map to sorted array
          entry.topFailedSteps = Object.entries(entry.failedSteps)
            .map(([stepId, count]) => ({ stepId, failures: count }))
            .sort((a: any, b: any) => b.failures - a.failures)
            .slice(0, 5);
          delete entry.failedSteps;
          delete entry.totalTimeMs;
          return entry;
        });

        // Most commonly triggered playbooks
        const mostTriggered = [...playbookStats]
          .sort((a: any, b: any) => b.totalExecutions - a.totalExecutions)
          .slice(0, 10);

        // Steps with highest failure rates across all executions
        const stepFailures: Record<string, { stepId: string; failures: number; total: number }> = {};
        for (const exec of orgExecs) {
          if (Array.isArray(exec.actionsExecuted)) {
            for (const action of exec.actionsExecuted as any[]) {
              const stepKey = action.nodeId || action.actionType || "unknown";
              if (!stepFailures[stepKey]) {
                stepFailures[stepKey] = { stepId: stepKey, failures: 0, total: 0 };
              }
              stepFailures[stepKey].total++;
              if (action.status === "failed") stepFailures[stepKey].failures++;
            }
          }
        }
        const highFailureSteps = Object.values(stepFailures)
          .filter((s) => s.total >= 2)
          .map((s) => ({ ...s, failureRate: Math.round((s.failures / s.total) * 100) }))
          .sort((a, b) => b.failureRate - a.failureRate)
          .slice(0, 10);

        // Execution time trend (last 30 executions)
        const recentCompleted = completed
          .sort(
            (a: any, b: any) => new Date(b.createdAt as string).getTime() - new Date(a.createdAt as string).getTime(),
          )
          .slice(0, 30);
        const timeTrend = recentCompleted.map((e: any) => ({
          executionId: e.id,
          playbookId: e.playbookId,
          executionTimeMs: e.executionTimeMs || 0,
          completedAt: e.updatedAt || e.createdAt,
        }));

        res.json({
          overview: {
            totalPlaybooks: allPlaybooks.length,
            activePlaybooks: allPlaybooks.filter((p: any) => p.status === "active").length,
            totalExecutions: orgExecs.length,
            completedExecutions: completed.length,
            failedExecutions: failed.length,
            avgExecutionTimeMs,
            successRate,
            failureRate,
          },
          mostTriggered,
          playbookStats,
          highFailureSteps,
          executionTimeTrend: timeTrend,
        });
      } catch (error) {
        logger.child("routes").error("Playbook analytics error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch playbook analytics" });
      }
    },
  );

  // ─── 20.8 Playbook → All Response Action Types ─────────────────────────────

  const ALL_RESPONSE_ACTION_TYPES = [
    {
      actionType: "isolate_host",
      label: "Isolate Endpoint",
      category: "endpoint",
      risk: "high",
      description: "Isolate a host from the network to contain a threat",
    },
    {
      actionType: "block_ip",
      label: "Block IP Address",
      category: "network",
      risk: "medium",
      description: "Block an IP address at the firewall or proxy",
    },
    {
      actionType: "block_domain",
      label: "Block Domain",
      category: "network",
      risk: "medium",
      description: "Block a domain via DNS sinkhole or proxy",
    },
    {
      actionType: "disable_user",
      label: "Disable User Account",
      category: "identity",
      risk: "high",
      description: "Disable a user account to prevent unauthorized access",
    },
    {
      actionType: "quarantine_file",
      label: "Quarantine File",
      category: "endpoint",
      risk: "medium",
      description: "Quarantine a suspicious file on the endpoint",
    },
    {
      actionType: "kill_process",
      label: "Kill Process",
      category: "endpoint",
      risk: "medium",
      description: "Terminate a running process on an endpoint",
    },
    {
      actionType: "quarantine_email",
      label: "Quarantine Email",
      category: "email",
      risk: "low",
      description: "Move a suspicious email to quarantine",
    },
    {
      actionType: "create_firewall_rule",
      label: "Create Firewall Rule",
      category: "network",
      risk: "high",
      description: "Create a new firewall rule to block traffic",
    },
    {
      actionType: "update_detection_rule",
      label: "Update Detection Rule",
      category: "detection",
      risk: "low",
      description: "Update or create a detection rule based on findings",
    },
    {
      actionType: "auto_triage",
      label: "Auto Triage",
      category: "workflow",
      risk: "low",
      description: "Automatically triage and categorize the alert or incident",
    },
    {
      actionType: "assign_analyst",
      label: "Assign Analyst",
      category: "workflow",
      risk: "low",
      description: "Assign an analyst to investigate",
    },
    {
      actionType: "change_status",
      label: "Change Status",
      category: "workflow",
      risk: "low",
      description: "Change the status of an incident or alert",
    },
    {
      actionType: "add_tag",
      label: "Add Tag",
      category: "workflow",
      risk: "low",
      description: "Add a tag to the resource for categorization",
    },
    {
      actionType: "escalate",
      label: "Escalate",
      category: "workflow",
      risk: "low",
      description: "Escalate to a higher tier analyst or manager",
    },
    {
      actionType: "create_jira_ticket",
      label: "Create Jira Ticket",
      category: "ticketing",
      risk: "low",
      description: "Create a Jira issue for tracking",
    },
    {
      actionType: "create_servicenow_ticket",
      label: "Create ServiceNow Ticket",
      category: "ticketing",
      risk: "low",
      description: "Create a ServiceNow incident or change request",
    },
    {
      actionType: "notify_slack",
      label: "Notify Slack",
      category: "notification",
      risk: "low",
      description: "Send a notification to a Slack channel",
    },
    {
      actionType: "notify_teams",
      label: "Notify Teams",
      category: "notification",
      risk: "low",
      description: "Send a notification to a Microsoft Teams channel",
    },
    {
      actionType: "notify_email",
      label: "Notify Email",
      category: "notification",
      risk: "low",
      description: "Send an email notification",
    },
    {
      actionType: "notify_pagerduty",
      label: "Notify PagerDuty",
      category: "notification",
      risk: "low",
      description: "Create a PagerDuty incident",
    },
    {
      actionType: "notify_webhook",
      label: "Notify Webhook",
      category: "notification",
      risk: "low",
      description: "Send a webhook notification to an external URL",
    },
  ];

  app.get(
    "/api/playbook-action-types",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req: Request, res: Response) => {
      try {
        const categories = Array.from(new Set(ALL_RESPONSE_ACTION_TYPES.map((a) => a.category)));
        const byCategory: Record<string, any[]> = {};
        for (const cat of categories) {
          byCategory[cat] = ALL_RESPONSE_ACTION_TYPES.filter((a) => a.category === cat);
        }
        res.json({
          actionTypes: ALL_RESPONSE_ACTION_TYPES,
          categories,
          byCategory,
          totalCount: ALL_RESPONSE_ACTION_TYPES.length,
        });
      } catch (error) {
        logger.child("routes").error("Action types error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch action types" });
      }
    },
  );

  // ─── 20.9 Playbook → Notification Channels ─────────────────────────────────

  const notificationTemplateStore = new Map<string, any[]>();

  app.get(
    "/api/playbooks/:id/notification-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const key = `${orgId}:${pb.id}`;
        const templates = notificationTemplateStore.get(key) || [];

        const channels = [
          {
            channel: "email",
            label: "Email",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{analyst}}", "{{timestamp}}", "{{url}}"],
          },
          {
            channel: "slack",
            label: "Slack",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{channel}}", "{{timestamp}}"],
          },
          {
            channel: "teams",
            label: "Microsoft Teams",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{timestamp}}"],
          },
          {
            channel: "pagerduty",
            label: "PagerDuty",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{urgency}}"],
          },
          {
            channel: "webhook",
            label: "Webhook",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{payload}}"],
          },
        ];

        res.json({
          playbookId: pb.id,
          playbookName: pb.name,
          availableChannels: channels,
          templates,
        });
      } catch (error) {
        logger.child("routes").error("Notification config error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch notification config" });
      }
    },
  );

  app.post(
    "/api/playbooks/:id/notification-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const { channel, subject, body, recipients, webhookUrl, urgency } = req.body;
        if (!channel || !body) {
          return res.status(400).json({ message: "channel and body are required" });
        }

        const validChannels = ["email", "slack", "teams", "pagerduty", "webhook"];
        if (!validChannels.includes(channel)) {
          return res.status(400).json({ message: `Invalid channel. Must be one of: ${validChannels.join(", ")}` });
        }

        const key = `${orgId}:${pb.id}`;
        if (!notificationTemplateStore.has(key)) notificationTemplateStore.set(key, []);

        const template = {
          id: `tmpl-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          channel,
          subject: subject || null,
          body,
          recipients: recipients || null,
          webhookUrl: webhookUrl || null,
          urgency: urgency || "high",
          createdAt: new Date().toISOString(),
          createdBy: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
        };

        notificationTemplateStore.get(key)!.push(template);

        await storage.createAuditLog({
          orgId,
          userId: (req as any).user?.id,
          userName: template.createdBy,
          action: "playbook_notification_template_created",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { templateId: template.id, channel },
        });

        res.status(201).json(template);
      } catch (error) {
        logger.child("routes").error("Notification template error", { error: String(error) });
        res.status(500).json({ message: "Failed to create notification template" });
      }
    },
  );

  app.delete(
    "/api/playbooks/:id/notification-templates/:templateId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const key = `${orgId}:${pb.id}`;
        const templates = notificationTemplateStore.get(key) || [];
        const idx = templates.findIndex((t: any) => t.id === req.params.templateId);
        if (idx < 0) {
          return res.status(404).json({ message: "Template not found" });
        }

        templates.splice(idx, 1);
        res.json({ success: true });
      } catch (error) {
        logger.child("routes").error("Notification template delete error", { error: String(error) });
        res.status(500).json({ message: "Failed to delete notification template" });
      }
    },
  );

  app.post(
    "/api/playbooks/:id/send-notification",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const { templateId, variables } = req.body;
        const key = `${orgId}:${pb.id}`;
        const templates = notificationTemplateStore.get(key) || [];
        const template = templates.find((t: any) => t.id === templateId);

        if (!template) {
          return res.status(404).json({ message: "Template not found" });
        }

        // Perform variable substitution
        let resolvedBody = template.body;
        let resolvedSubject = template.subject || "";
        const vars = variables || {};
        for (const [varName, varValue] of Object.entries(vars)) {
          const placeholder = `{{${varName}}}`;
          resolvedBody = resolvedBody.replace(new RegExp(placeholder.replace(/[{}]/g, "\\$&"), "g"), String(varValue));
          resolvedSubject = resolvedSubject.replace(
            new RegExp(placeholder.replace(/[{}]/g, "\\$&"), "g"),
            String(varValue),
          );
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const context: ActionContext = {
          orgId,
          userId: user?.id,
          userName,
          storage,
        };

        const actionType = `notify_${template.channel}`;
        const config: Record<string, string> = {
          message: resolvedBody,
          subject: resolvedSubject,
        };
        if (template.recipients) config.recipient = template.recipients;
        if (template.webhookUrl) config.webhookUrl = template.webhookUrl;
        if (template.urgency) config.urgency = template.urgency;

        const result = await dispatchAction(actionType, config, context);

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "playbook_notification_sent",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { templateId, channel: template.channel, result: result.status },
        });

        res.json({ templateId, channel: template.channel, result, resolvedBody, resolvedSubject });
      } catch (error) {
        logger.child("routes").error("Send notification error", { error: String(error) });
        res.status(500).json({ message: "Failed to send notification" });
      }
    },
  );

  // ─── 20.10 Playbook → Change Management Integration ────────────────────────

  const changeTicketStore = new Map<string, any[]>();

  app.get(
    "/api/playbook-change-tickets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        const { playbookId, status } = req.query;
        let filtered = tickets;
        if (playbookId) filtered = filtered.filter((t: any) => t.playbookId === playbookId);
        if (status) filtered = filtered.filter((t: any) => t.status === status);
        res.json({ tickets: filtered, total: filtered.length });
      } catch (error) {
        logger.child("routes").error("Change tickets error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch change tickets" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const {
          playbookId,
          executionId,
          changeType,
          summary,
          description,
          impactAssessment,
          rollbackPlan,
          requiresApproval,
        } = req.body;

        if (!playbookId || !changeType || !summary) {
          return res.status(400).json({ message: "playbookId, changeType, and summary are required" });
        }

        const pb = await storage.getPlaybook(p(playbookId));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const validChangeTypes = [
          "firewall_rule",
          "account_disable",
          "network_block",
          "endpoint_isolation",
          "detection_update",
          "configuration_change",
        ];
        if (!validChangeTypes.includes(changeType)) {
          return res
            .status(400)
            .json({ message: `Invalid changeType. Must be one of: ${validChangeTypes.join(", ")}` });
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";

        const ticket = {
          id: `CHG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 5).toUpperCase()}`,
          orgId,
          playbookId,
          playbookName: pb.name,
          executionId: executionId || null,
          changeType,
          summary,
          description: description || null,
          impactAssessment: impactAssessment || "Low impact — automated security response",
          rollbackPlan: rollbackPlan || "Revert via playbook rollback mechanism",
          requiresApproval: requiresApproval !== false,
          status: requiresApproval !== false ? "pending_approval" : "approved",
          requestedBy: userName,
          requestedAt: new Date().toISOString(),
          approvedBy: requiresApproval !== false ? null : "auto-approved",
          approvedAt: requiresApproval !== false ? null : new Date().toISOString(),
          implementedAt: null,
          closedAt: null,
          changeLog: [
            {
              action: "created",
              actor: userName,
              timestamp: new Date().toISOString(),
              details: { changeType, summary },
            },
          ],
        };

        const key = `org:${orgId}`;
        if (!changeTicketStore.has(key)) changeTicketStore.set(key, []);
        changeTicketStore.get(key)!.push(ticket);

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "change_ticket_created",
          resourceType: "change_ticket",
          resourceId: ticket.id,
          details: { playbookId, changeType, summary, requiresApproval: ticket.requiresApproval },
        });

        res.status(201).json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket create error", { error: String(error) });
        res.status(500).json({ message: "Failed to create change ticket" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets/:ticketId/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        const ticket = tickets.find((t: any) => t.id === req.params.ticketId);

        if (!ticket) {
          return res.status(404).json({ message: "Change ticket not found" });
        }
        if (ticket.status !== "pending_approval") {
          return res.status(400).json({ message: `Ticket is already ${ticket.status}` });
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin";
        const { decision, note } = req.body;

        if (!decision || !["approved", "rejected"].includes(decision)) {
          return res.status(400).json({ message: "decision must be 'approved' or 'rejected'" });
        }

        ticket.status = decision;
        ticket.approvedBy = userName;
        ticket.approvedAt = new Date().toISOString();
        ticket.changeLog.push({
          action: decision,
          actor: userName,
          timestamp: new Date().toISOString(),
          details: { note: note || null },
        });

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: `change_ticket_${decision}`,
          resourceType: "change_ticket",
          resourceId: ticket.id,
          details: { decision, note },
        });

        res.json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket approve error", { error: String(error) });
        res.status(500).json({ message: "Failed to approve change ticket" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets/:ticketId/implement",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        const ticket = tickets.find((t: any) => t.id === req.params.ticketId);

        if (!ticket) {
          return res.status(404).json({ message: "Change ticket not found" });
        }
        if (ticket.status !== "approved") {
          return res.status(400).json({ message: "Ticket must be approved before implementation" });
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";

        ticket.status = "implemented";
        ticket.implementedAt = new Date().toISOString();
        ticket.changeLog.push({
          action: "implemented",
          actor: userName,
          timestamp: new Date().toISOString(),
          details: req.body.notes ? { notes: req.body.notes } : {},
        });

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "change_ticket_implemented",
          resourceType: "change_ticket",
          resourceId: ticket.id,
        });

        res.json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket implement error", { error: String(error) });
        res.status(500).json({ message: "Failed to implement change ticket" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets/:ticketId/close",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        const ticket = tickets.find((t: any) => t.id === req.params.ticketId);

        if (!ticket) {
          return res.status(404).json({ message: "Change ticket not found" });
        }

        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";

        ticket.status = "closed";
        ticket.closedAt = new Date().toISOString();
        ticket.changeLog.push({
          action: "closed",
          actor: userName,
          timestamp: new Date().toISOString(),
          details: req.body.resolution ? { resolution: req.body.resolution } : {},
        });

        res.json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket close error", { error: String(error) });
        res.status(500).json({ message: "Failed to close change ticket" });
      }
    },
  );
}

function extractNodes(actions: unknown): any[] {
  if (!Array.isArray(actions) || actions.length === 0) return [];
  const first = actions[0] as any;
  if (first && typeof first === "object" && "nodes" in first) {
    return first.nodes || [];
  }
  return actions;
}
