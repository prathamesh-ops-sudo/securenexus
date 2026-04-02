import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { validatePathId } from "../../request-validator";
import { extractNodes } from "./utils";

export function registerPlaybooksSimulationsRoutes(app: Express): void {
  // Playbook Simulations CRUD

  app.get(
    "/api/playbooks/:playbookId/simulations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("playbookId"),
    async (req: Request, res: Response) => {
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
    async (req: Request, res: Response) => {
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
    async (req: Request, res: Response) => {
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
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const playbookId = p(req.params.playbookId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const userId = (req as any).user?.id;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const userName = (req as any).user?.firstName
          ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
            `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const simulatedActions: any[] = [];
        const startTime = Date.now();

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
        if (isGraphFormat) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

  // Playbook Dry-Run / Simulation Mode (enhanced)

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

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const { parameters, scenarioName } = req.body;

        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const simulatedActions: any[] = [];
        const startTime = Date.now();

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;

        if (isGraphFormat) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const graph = actionsArr[0] as any;
          const nodes = graph.nodes || [];
          const edges = graph.edges || [];
          const adjacency: Record<string, string[]> = {};
          for (const edge of edges) {
            if (!adjacency[edge.source]) adjacency[edge.source] = [];
            adjacency[edge.source].push(edge.target);
          }
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const targetNodes = new Set(edges.map((e: any) => e.target));
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const startNodes = nodes.filter((n: any) => !targetNodes.has(n.id) || n.type === "trigger");
          const visited = new Set<string>();
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const queue = startNodes.map((n: any) => n.id);
          let stepNum = 0;

          while (queue.length > 0 && stepNum < 50) {
            const nodeId = queue.shift()!;
            if (visited.has(nodeId)) continue;
            visited.add(nodeId);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const node = nodes.find((n: any) => n.id === nodeId);
            if (!node) continue;
            stepNum++;

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const simResult: any = {
              step: stepNum,
              nodeId: node.id,
              nodeType: node.type,
              label: node.data?.label || node.type,
              actionType: node.data?.actionType || node.type,
              status: "simulated",
              wouldExecute: node.type === "action",
              wouldBlock: node.type === "approval",
              estimatedDurationMs: 2000 + stepNum * 500,
              timestamp: new Date(startTime + stepNum * 1000).toISOString(),
              impact: [],
            };

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
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const actionObj = action as any;
            const actionType = actionObj.type || actionObj.actionType || "unknown";
            simulatedActions.push({
              step: stepNum,
              actionType,
              label: actionObj.label || actionType,
              status: "simulated",
              wouldExecute: true,
              estimatedDurationMs: 2000 + stepNum * 500,
              timestamp: new Date(startTime + stepNum * 1000).toISOString(),
              riskLevel: "medium",
              impact: [{ type: "informational", description: `Would execute: ${actionType}` }],
            });
          }
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const totalDuration = simulatedActions.reduce((sum: number, a: any) => sum + (a.estimatedDurationMs || 0), 0);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const highRiskSteps = simulatedActions.filter((a: any) => a.riskLevel === "high");
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const approvalGates = simulatedActions.filter((a: any) => a.wouldBlock);

        const simulation = await storage.createPlaybookSimulation({
          playbookId: pb.id,
          orgId,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          simulatedActions: simulatedActions as any,
          impactAnalysis: {
            totalSteps: simulatedActions.length,
            estimatedDurationMs: totalDuration,
            highRiskSteps: highRiskSteps.length,
            approvalGates: approvalGates.length,
            scenarioName: scenarioName || "Manual simulation",
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            destructiveActions: simulatedActions.filter((a: any) =>
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

  // Playbook Step Timeout Handling

  const stepTimeoutDefaults: Record<string, number> = {
    action: 30000,
    condition: 5000,
    approval: 0,
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;

        if (isGraphFormat) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const graph = { ...(actionsArr[0] as any) };
          const nodes = [...(graph.nodes || [])];
          for (const stepUpdate of steps) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          await storage.updatePlaybook(pb.id, { actions: [graph] } as any);
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
}
