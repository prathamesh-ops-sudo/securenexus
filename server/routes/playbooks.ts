import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../request-validator";
import { dispatchAction, type ActionContext } from "../action-dispatcher";
import { canRollback, createRollbackRecord } from "../rollback-engine";

export function registerPlaybooksRoutes(app: Express): void {
  // Playbooks (Phase 13 - SOAR-Lite)
  app.get("/api/playbooks", isAuthenticated, async (_req, res) => {
    try { res.json(await storage.getPlaybooks()); }
    catch (error) { res.status(500).json({ message: "Failed to fetch playbooks" }); }
  });

  app.get("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb) return res.status(404).json({ message: "Playbook not found" });
      res.json(pb);
    } catch (error) { res.status(500).json({ message: "Failed to fetch playbook" }); }
  });

  app.post("/api/playbooks", isAuthenticated, validateBody(bodySchemas.playbookCreate), async (req, res) => {
    try {
      const { name, description, trigger, conditions, actions, status } = (req as any).validatedBody;
      const playbook = await storage.createPlaybook({
        name, description, trigger, conditions, actions, status: status || "draft",
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "playbook_created",
        resourceType: "playbook", resourceId: playbook.id,
        details: { name, trigger },
      });
      res.status(201).json(playbook);
    } catch (error) { res.status(500).json({ message: "Failed to create playbook" }); }
  });

  app.patch("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const existing = await storage.getPlaybook(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Playbook not found" });
      const updated = await storage.updatePlaybook(p(req.params.id), {
        ...req.body, updatedAt: new Date(),
      });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update playbook" }); }
  });

  app.delete("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const deleted = await storage.deletePlaybook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Playbook not found" });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "playbook_deleted",
        resourceType: "playbook", resourceId: p(req.params.id),
      });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete playbook" }); }
  });

  app.post("/api/playbooks/:id/execute", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb) return res.status(404).json({ message: "Playbook not found" });
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
              executedActions.push({ nodeId, actionType: node.data.actionType, status: "simulated", message: `[Dry Run] Would execute: ${node.data.label}`, executedAt: new Date().toISOString() });
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
            executedActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
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
          const config = typeof actionObj.config === "string" ? 
            (() => { try { return JSON.parse(actionObj.config); } catch { return { raw: actionObj.config }; } })() :
            (actionObj.config || {});
          if (isDryRun) {
            executedActions.push({ actionType, status: "simulated", message: `[Dry Run] Would execute: ${actionType}`, executedAt: new Date().toISOString() });
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
          result: { totalActions: executedActions.length, completedActions: executedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
          executionTimeMs: Date.now() - startTime,
        });
      }

      await storage.updatePlaybook(pb.id, { lastTriggeredAt: new Date(), triggerCount: (pb.triggerCount || 0) + 1 } as any);
      await storage.createAuditLog({
        userId: user?.id,
        userName: context.userName,
        action: "playbook_executed",
        resourceType: "playbook",
        resourceId: pb.id,
        details: { name: pb.name, trigger: "manual", actionsCount: executedActions.length, dryRun: isDryRun, paused: pausedAtApproval },
      });
      const updatedExecution = await storage.getPlaybookExecution(executionId);
      res.json(updatedExecution || execution);
    } catch (error) {
      logger.child("routes").error("Playbook execution error", { error: String(error) });
      res.status(500).json({ message: "Failed to execute playbook" });
    }
  });

  app.get("/api/playbook-executions", isAuthenticated, validateQuery(querySchemas.playbookExecutions), async (req, res) => {
    try {
      const { playbookId, limit } = (req as any).validatedQuery;
      res.json(await storage.getPlaybookExecutions(playbookId, limit));
    } catch (error) { res.status(500).json({ message: "Failed to fetch executions" }); }
  });

  app.get("/api/playbook-approvals", isAuthenticated, validateQuery(querySchemas.approvalStatus), async (req, res) => {
    try {
      const { status } = (req as any).validatedQuery;
      const approvals = await storage.getPlaybookApprovals(status);
      res.json(approvals);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbook approvals" });
    }
  });

  app.post("/api/playbook-approvals/:id/decide", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.approvalDecision), async (req, res) => {
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
            const resumeFrom = pausedNodeId ? (adjacency[pausedNodeId] || []) : [];
            const existingActions = Array.isArray(execution.actionsExecuted) ? execution.actionsExecuted as any[] : [];
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
                  newActions.push({ nodeId, actionType: node.data.actionType, status: "simulated", message: `[Dry Run] Would execute: ${node.data.label}`, executedAt: new Date().toISOString() });
                } else {
                  const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
                  newActions.push({ nodeId, ...result });
                }
                execCount++;
              } else if (node.type === "condition") {
                const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
                for (const edge of trueEdges) { queue.push(edge.target); }
                newActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
                execCount++;
                continue;
              }
              const children = adjacency[nodeId] || [];
              for (const child of children) { queue.push(child); }
            }
            const mergedActions = [...existingActions, ...newActions];
            await storage.updatePlaybookExecution(execution.id, {
              status: "completed",
              pausedAtNodeId: null,
              actionsExecuted: mergedActions,
              result: { totalActions: mergedActions.length, completedActions: mergedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
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
  });

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
      const resumeFrom = pausedNodeId ? (adjacency[pausedNodeId] || []) : [];
      const existingActions = Array.isArray(execution.actionsExecuted) ? execution.actionsExecuted as any[] : [];
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
            newActions.push({ nodeId, actionType: node.data.actionType, status: "simulated", message: `[Dry Run] Would execute: ${node.data.label}`, executedAt: new Date().toISOString() });
          } else {
            const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
            newActions.push({ nodeId, ...result });
          }
          execCount++;
        } else if (node.type === "condition") {
          const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
          for (const edge of trueEdges) { queue.push(edge.target); }
          newActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
          execCount++;
          continue;
        }
        const children = adjacency[nodeId] || [];
        for (const child of children) { queue.push(child); }
      }

      const mergedActions = [...existingActions, ...newActions];
      const updated = await storage.updatePlaybookExecution(execution.id, {
        status: "completed",
        pausedAtNodeId: null,
        actionsExecuted: mergedActions,
        result: { totalActions: mergedActions.length, completedActions: mergedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
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

      const actionsExecuted = Array.isArray(execution.actionsExecuted) ? execution.actionsExecuted as any[] : [];
      const rollbackEligible = actionsExecuted.filter((a: any) => canRollback(a.actionType));

      if (rollbackEligible.length === 0) {
        return res.json({ message: "No rollback-eligible actions found", rollbacks: [] });
      }

      const orgId = getOrgId(req);
      const rollbacks = [];
      for (const action of rollbackEligible) {
        const target = action.details?.target || action.details?.hostname || action.details?.ip || action.nodeId || "unknown";
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
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      logger.child("routes").error("Rollback creation error", { error: String(error) });
      res.status(500).json({ message: "Failed to create rollback records" });
    }
  });

}
