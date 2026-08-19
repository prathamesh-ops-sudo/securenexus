import type { Express } from "express";
import { logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../../rbac";

import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../../request-validator";
import { dispatchAction, type ActionContext } from "../../action-dispatcher";

export function registerPlaybooksApprovalsRoutes(app: Express): void {
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
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
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
}
