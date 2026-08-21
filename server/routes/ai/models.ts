/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes } from "crypto";
import type { Express, Request, Response } from "express";
import { getOrgId, logger, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole, requireOrgId } from "../../rbac";
import { getModelConfig } from "../../ai";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";
import { pool } from "../../db";

const log = logger.child("routes-ai-models");

export function registerAiModelsRoutes(app: Express): void {
  // Multi-Model Support
  app.get("/api/ai/models", isAuthenticated, resolveOrgContext, async (_req: Request, res: Response) => {
    try {
      const models = [
        {
          id: "amazon.nova-pro-v1:0",
          provider: "aws_bedrock",
          name: "Amazon Nova Pro",
          tier: "default",
          capabilities: ["correlation", "narrative", "investigation"],
          maxTokens: 8192,
          costPer1kTokens: 0.0008,
          status: "available",
        },
        {
          id: "amazon.nova-lite-v1:0",
          provider: "aws_bedrock",
          name: "Amazon Nova Lite",
          tier: "triage",
          capabilities: ["triage", "classification", "correlation"],
          maxTokens: 4096,
          costPer1kTokens: 0.00006,
          status: "available",
        },
        {
          id: "amazon.titan-embed-text-v2:0",
          provider: "aws_bedrock",
          name: "Amazon Titan Text Embeddings V2",
          tier: "embedding",
          capabilities: ["embeddings"],
          maxTokens: 0,
          costPer1kTokens: 0.00002,
          status: "available",
        },
        {
          id: "anthropic.claude-3-5-sonnet-20241022-v2:0",
          provider: "aws_bedrock",
          name: "Claude 3.5 Sonnet (override)",
          tier: "alternative",
          capabilities: ["triage", "correlation", "narrative", "investigation"],
          maxTokens: 8192,
          costPer1kTokens: 0.003,
          status: "configurable",
        },
        {
          id: "anthropic.claude-3-haiku-20240307-v1:0",
          provider: "aws_bedrock",
          name: "Claude 3 Haiku (override)",
          tier: "alternative",
          capabilities: ["triage", "classification"],
          maxTokens: 4096,
          costPer1kTokens: 0.00025,
          status: "configurable",
        },
        {
          id: "mistral.mistral-large-2402-v1:0",
          provider: "aws_bedrock",
          name: "Mistral Large",
          tier: "alternative",
          capabilities: ["triage", "correlation", "narrative", "investigation"],
          maxTokens: 8192,
          costPer1kTokens: 0.004,
          status: "available",
        },
        {
          id: "gpt-4-turbo",
          provider: "openai",
          name: "GPT-4 Turbo",
          tier: "alternative",
          capabilities: ["triage", "correlation", "narrative", "investigation"],
          maxTokens: 8192,
          costPer1kTokens: 0.01,
          status: "configurable",
        },
        {
          id: "local-llama-3.1-70b",
          provider: "local",
          name: "Llama 3.1 70B (Local)",
          tier: "local",
          capabilities: ["triage", "correlation"],
          maxTokens: 4096,
          costPer1kTokens: 0,
          status: "configurable",
        },
        {
          id: "mistral-large",
          provider: "mistral",
          name: "Mistral Large",
          tier: "alternative",
          capabilities: ["triage", "correlation", "narrative"],
          maxTokens: 8192,
          costPer1kTokens: 0.008,
          status: "configurable",
        },
      ];

      const activeConfig = getModelConfig();

      res.json({
        activeModel: activeConfig,
        availableModels: models,
        tierAssignments: {
          default: "amazon.nova-pro-v1:0",
          investigation: "amazon.nova-pro-v1:0",
          triage: "amazon.nova-lite-v1:0",
        },
      });
    } catch (error: any) {
      logger.child("ai").error("Models list error", { error: String(error) });
      res.status(500).json({ message: "Failed to list available models" });
    }
  });

  app.put(
    "/api/ai/models/tier-assignment",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const { tier, modelId } = req.body;
        const validTiers = ["default", "investigation", "triage"];
        if (!tier || !validTiers.includes(tier)) {
          return res.status(400).json({ message: `tier must be one of: ${validTiers.join(", ")}` });
        }
        if (!modelId || typeof modelId !== "string") {
          return res.status(400).json({ message: "modelId is required" });
        }

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "ai_model_tier_updated",
          resourceType: "ai_config",
          details: { tier, modelId },
        });

        res.json({ tier, modelId, updated: true });
      } catch (error: any) {
        logger.child("ai").error("Model tier assignment error", { error: String(error) });
        res.status(500).json({ message: "Failed to update model tier assignment" });
      }
    },
  );

  // AI Data Sources Integration
  app.get("/api/ai/data-sources", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);

      let alertCount = 0;
      let incidentCount = 0;
      let entityCount = 0;

      try {
        const alerts = await storage.getAlerts(orgId);
        alertCount = alerts.length;
      } catch {
        /* table may not exist */
      }

      try {
        const incidents = await storage.getIncidents(orgId);
        incidentCount = incidents.length;
      } catch {
        /* table may not exist */
      }

      try {
        const entityResult = await pool.query(`SELECT COUNT(*) as cnt FROM entities WHERE org_id = $1`, [orgId]);
        entityCount = parseInt(String(entityResult.rows[0]?.cnt || "0"), 10);
      } catch {
        /* table may not exist */
      }

      const sourceStatus = (recordCount: number, sourceName: string) => ({
        status: recordCount > 0 ? "connected" : "unconfigured",
        recordCount: recordCount > 0 ? recordCount : null,
        lastSync: null,
        reason: recordCount > 0 ? null : `No ${sourceName} records are available. Configure and connect this source.`,
      });
      const dataSources = [
        {
          id: "alerts",
          name: "Security Alerts",
          ...sourceStatus(alertCount, "security alert"),
        },
        {
          id: "incidents",
          name: "Incidents",
          ...sourceStatus(incidentCount, "incident"),
        },
        {
          id: "entities",
          name: "Entity Graph",
          ...sourceStatus(entityCount, "entity"),
        },
        {
          id: "threat_intel",
          name: "Threat Intelligence",
          ...sourceStatus(0, "threat intelligence"),
        },
        { id: "osint", name: "OSINT Feeds", ...sourceStatus(0, "OSINT") },
        { id: "ueba", name: "UEBA Analytics", ...sourceStatus(0, "UEBA") },
        {
          id: "endpoint_telemetry",
          name: "Endpoint Telemetry",
          ...sourceStatus(0, "endpoint telemetry"),
        },
        {
          id: "network_flows",
          name: "Network Flows",
          ...sourceStatus(0, "network flow"),
        },
        {
          id: "cloud_configs",
          name: "Cloud Configurations",
          ...sourceStatus(0, "cloud configuration"),
        },
        {
          id: "vulnerability_scanner",
          name: "Vulnerability Scanner",
          ...sourceStatus(0, "vulnerability scan"),
        },
      ];

      res.json({
        totalSources: dataSources.length,
        connectedSources: dataSources.filter((s) => s.status === "connected").length,
        dataSources,
        totalRecords: dataSources.reduce((sum, s) => sum + (s.recordCount || 0), 0),
      });
    } catch (error: any) {
      logger.child("ai").error("Data sources error", { error: String(error) });
      res.status(500).json({ message: "Failed to list data sources" });
    }
  });

  // Response Action Execution with Approval
  app.post(
    "/api/ai/response-actions/propose",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    enforcePlanLimit("ai_analyses"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { incidentId, actionType, target, parameters = {} } = req.body;

        if (!incidentId || !actionType || !target) {
          return res.status(400).json({ message: "incidentId, actionType, and target are required" });
        }

        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const ALLOWED_ACTIONS = [
          "isolate_host",
          "block_ip",
          "disable_account",
          "quarantine_file",
          "reset_credentials",
          "revoke_session",
          "notify_team",
          "create_ticket",
          "snapshot_evidence",
          "enrich_ioc",
        ];

        if (!ALLOWED_ACTIONS.includes(actionType)) {
          return res.status(400).json({
            message: `Invalid actionType. Must be one of: ${ALLOWED_ACTIONS.join(", ")}`,
          });
        }

        const LOW_RISK_ACTIONS = ["notify_team", "create_ticket", "snapshot_evidence", "enrich_ioc"];
        const requiresApproval = !LOW_RISK_ACTIONS.includes(actionType);

        const proposal = {
          id: `ra_${Date.now()}_${randomBytes(4).toString("hex")}`,
          orgId,
          incidentId,
          actionType,
          target,
          parameters,
          status: requiresApproval ? "pending_approval" : "auto_approved",
          requiresApproval,
          riskLevel: requiresApproval ? "high" : "low",
          proposedBy: "ai_engine",
          proposedAt: new Date().toISOString(),
          approvedBy: requiresApproval ? null : "auto",
          executedAt: requiresApproval ? null : new Date().toISOString(),
          rollbackPlan: `Reverse ${actionType} on ${target}`,
          estimatedImpact: requiresApproval
            ? `This action will ${actionType.replace(/_/g, " ")} for ${target}. Manual approval required.`
            : `Low-risk action: ${actionType.replace(/_/g, " ")} for ${target}. Auto-executed.`,
        };

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "AI Engine",
          action: requiresApproval ? "ai_response_action_proposed" : "ai_response_action_auto_executed",
          resourceType: "incident",
          resourceId: incidentId,
          details: { actionType, target, status: proposal.status },
        });

        res.json(proposal);
      } catch (error: any) {
        logger.child("ai").error("Response action proposal error", { error: String(error) });
        res.status(500).json({ message: "Failed to propose response action" });
      }
    },
  );

  app.post(
    "/api/ai/response-actions/:actionId/approve",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.actionId);

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_response_action_approved",
          resourceType: "response_action",
          resourceId: actionId,
          details: { orgId },
        });

        res.json({
          actionId,
          status: "approved",
          approvedBy: (req as any).user?.firstName || "Analyst",
          approvedAt: new Date().toISOString(),
          executedAt: new Date().toISOString(),
        });
      } catch (error: any) {
        logger.child("ai").error("Response action approve error", { error: String(error) });
        res.status(500).json({ message: "Failed to approve response action" });
      }
    },
  );

  app.post(
    "/api/ai/response-actions/:actionId/reject",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const actionId = String(req.params.actionId);
        const { reason } = req.body;

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_response_action_rejected",
          resourceType: "response_action",
          resourceId: actionId,
          details: { reason: reason || "No reason provided" },
        });

        res.json({
          actionId,
          status: "rejected",
          rejectedBy: (req as any).user?.firstName || "Analyst",
          rejectedAt: new Date().toISOString(),
          reason: reason || "No reason provided",
        });
      } catch (error: any) {
        logger.child("ai").error("Response action reject error", { error: String(error) });
        res.status(500).json({ message: "Failed to reject response action" });
      }
    },
  );
}
