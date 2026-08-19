import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { querySchemas, validatePathId, validateQuery } from "../../request-validator";
import { dispatchAction, type ActionContext } from "../../action-dispatcher";
import { canRollback, createRollbackRecord } from "../../rollback-engine";
import { extractNodes } from "./utils";

export function registerPlaybooksExecutionRoutes(app: Express): void {
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
    resolveOrgContext,
    requireOrgId,
    validateQuery(querySchemas.playbookExecutions),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { playbookId, limit } = (req as any).validatedQuery;
        res.json(await storage.getPlaybookExecutions(orgId, playbookId, limit));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch executions" });
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
        const allExecs = await storage.getPlaybookExecutions(orgId, undefined, 200);
        const orgPlaybooks = await storage.getPlaybooks(orgId);
        const orgExecs = allExecs;

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
        const allExecs = await storage.getPlaybookExecutions(orgId, undefined, 500);
        const orgExecs = allExecs;

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
}
