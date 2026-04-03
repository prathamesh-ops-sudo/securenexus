import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { storage } from "../storage";
import {
  getToolCatalog,
  getToolById,
  verifyTool,
  type ToolRiskLevel,
  type TrustBoundary,
  type InvocationVerdict,
  type AnomalyType,
} from "../agent-tool-security-engine";

const VALID_RISK_LEVELS: ToolRiskLevel[] = ["low", "medium", "high", "critical"];
const VALID_BOUNDARIES: TrustBoundary[] = ["internal", "external", "privileged", "sandboxed"];
const VALID_VERDICTS: InvocationVerdict[] = ["allowed", "denied", "throttled", "flagged"];
const VALID_ANOMALY_TYPES: AnomalyType[] = [
  "unusual_chaining",
  "scope_escalation",
  "rate_spike",
  "destination_drift",
  "payload_anomaly",
];
const VALID_BOUNDARY_ACTIONS = ["allow", "deny", "require_approval"] as const;

export function registerAgentToolSecurityRoutes(app: Express): void {
  app.get("/api/agent-tool-security/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [totalInvocations, totalAnomalies, unacknowledgedAnomalies, policies, boundaryRules] = await Promise.all([
        storage.countAgentToolInvocations(orgId),
        storage.countAgentToolAnomalies(orgId),
        storage.countAgentToolAnomalies(orgId, true),
        storage.getAgentToolPoliciesList(orgId),
        storage.getAgentTrustBoundaryRulesList(orgId),
      ]);
      res.json({
        totalInvocations,
        totalAnomalies,
        unacknowledgedAnomalies,
        totalPolicies: policies.length,
        totalBoundaryRules: boundaryRules.length,
      });
    } catch (error) {
      logger.child("routes").error("Agent tool stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch agent tool security stats" });
    }
  });

  // Tool catalog is static reference data — kept on engine
  app.get("/api/agent-tool-security/tools", isAuthenticated, async (req, res) => {
    try {
      const riskLevel =
        typeof req.query.riskLevel === "string" && VALID_RISK_LEVELS.includes(req.query.riskLevel as ToolRiskLevel)
          ? (req.query.riskLevel as ToolRiskLevel)
          : undefined;
      const trustBoundary =
        typeof req.query.trustBoundary === "string" &&
        VALID_BOUNDARIES.includes(req.query.trustBoundary as TrustBoundary)
          ? (req.query.trustBoundary as TrustBoundary)
          : undefined;
      res.json(getToolCatalog(riskLevel, trustBoundary));
    } catch (error) {
      logger.child("routes").error("Tool catalog error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch tool catalog" });
    }
  });

  app.get("/api/agent-tool-security/tools/:id", isAuthenticated, async (req, res) => {
    try {
      const id = String(req.params.id);
      const tool = getToolById(id);
      if (!tool) return res.status(404).json({ message: "Tool not found" });
      res.json(tool);
    } catch (error) {
      logger.child("routes").error("Get tool error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch tool" });
    }
  });

  app.post("/api/agent-tool-security/tools/:id/verify", isAuthenticated, async (req, res) => {
    try {
      const id = String(req.params.id);
      const result = verifyTool(id);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Verify tool error", { error: String(error) });
      res.status(500).json({ message: "Failed to verify tool" });
    }
  });

  // Invocations — persisted to DB
  app.get("/api/agent-tool-security/invocations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 100;
      const invocations = await storage.getAgentToolInvocations(orgId, limit);
      // Apply client-side filters
      let filtered = invocations;
      if (typeof req.query.toolId === "string") {
        filtered = filtered.filter((i) => i.toolId === req.query.toolId);
      }
      if (typeof req.query.agentId === "string") {
        filtered = filtered.filter((i) => i.agentId === req.query.agentId);
      }
      if (typeof req.query.verdict === "string" && VALID_VERDICTS.includes(req.query.verdict as InvocationVerdict)) {
        filtered = filtered.filter((i) => i.verdict === req.query.verdict);
      }
      res.json(filtered);
    } catch (error) {
      logger.child("routes").error("List invocations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list invocations" });
    }
  });

  app.get("/api/agent-tool-security/invocations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const inv = await storage.getAgentToolInvocation(id, orgId);
      if (!inv) return res.status(404).json({ message: "Invocation not found" });
      res.json(inv);
    } catch (error) {
      logger.child("routes").error("Get invocation error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch invocation" });
    }
  });

  app.post("/api/agent-tool-security/invocations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;
      if (!body.agentId || typeof body.agentId !== "string") {
        return res.status(400).json({ message: "agentId is required" });
      }
      if (!body.toolId || typeof body.toolId !== "string") {
        return res.status(400).json({ message: "toolId is required" });
      }
      // Verify tool exists in catalog
      const tool = getToolById(body.toolId);
      if (!tool) return res.status(404).json({ message: "Tool not found" });

      // Check policy for this tool
      const policy = await storage.getAgentToolPolicyByTool(orgId, body.toolId);
      let verdict: InvocationVerdict = "allowed";
      if (policy && policy.blocked) {
        verdict = "denied";
      }

      const invocation = await storage.createAgentToolInvocation({
        orgId,
        toolId: body.toolId,
        toolName: tool.name,
        agentId: body.agentId,
        verdict,
        inputHash: typeof body.input === "string" ? body.input.substring(0, 64) : undefined,
        outputSummary: typeof body.outputSummary === "string" ? body.outputSummary : undefined,
        durationMs: typeof body.durationMs === "number" ? body.durationMs : undefined,
        riskScore: typeof body.riskScore === "number" ? body.riskScore : 0,
        metadata: {
          agentName: body.agentName || "",
          scopes: Array.isArray(body.scopes) ? body.scopes : [],
          destination: body.destination || null,
          chainId: body.chainId || null,
          parentInvocationId: body.parentInvocationId || null,
        },
      });
      res.status(201).json(invocation);
    } catch (error) {
      logger.child("routes").error("Record invocation error", { error: String(error) });
      res.status(500).json({ message: "Failed to record invocation" });
    }
  });

  // Anomalies — persisted to DB
  app.get("/api/agent-tool-security/anomalies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const unacknowledgedOnly = req.query.acknowledged === "false";
      const acknowledgedOnly = req.query.acknowledged === "true";
      let anomalies = await storage.getAgentToolAnomalies(orgId, unacknowledgedOnly);
      if (acknowledgedOnly) {
        anomalies = anomalies.filter((a) => a.acknowledged);
      }
      // Apply client-side filters
      let filtered = anomalies;
      if (typeof req.query.type === "string" && VALID_ANOMALY_TYPES.includes(req.query.type as AnomalyType)) {
        filtered = filtered.filter((a) => a.anomalyType === req.query.type);
      }
      if (typeof req.query.severity === "string" && VALID_RISK_LEVELS.includes(req.query.severity as ToolRiskLevel)) {
        filtered = filtered.filter((a) => a.severity === req.query.severity);
      }
      res.json(filtered);
    } catch (error) {
      logger.child("routes").error("List anomalies error", { error: String(error) });
      res.status(500).json({ message: "Failed to list anomalies" });
    }
  });

  app.post("/api/agent-tool-security/anomalies/:id/acknowledge", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const userId = typeof req.body.acknowledgedBy === "string" ? req.body.acknowledgedBy : "system";
      const result = await storage.acknowledgeAgentToolAnomaly(id, orgId, userId);
      if (!result) return res.status(404).json({ message: "Anomaly not found" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Acknowledge anomaly error", { error: String(error) });
      res.status(500).json({ message: "Failed to acknowledge anomaly" });
    }
  });

  // Policies — persisted to DB
  app.get("/api/agent-tool-security/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policies = await storage.getAgentToolPoliciesList(orgId);
      res.json(policies);
    } catch (error) {
      logger.child("routes").error("List policies error", { error: String(error) });
      res.status(500).json({ message: "Failed to list policies" });
    }
  });

  app.patch("/api/agent-tool-security/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const toolId = String(req.params.id);
      const body = req.body;

      // Build the upsert data
      const data: Record<string, unknown> = { orgId, toolId };
      if (typeof body.maxCallsPerMinute === "number") data.maxCallsPerMinute = body.maxCallsPerMinute;
      if (typeof body.maxCallsPerHour === "number") data.maxCallsPerHour = body.maxCallsPerHour;
      if (typeof body.requireApprovalAboveRisk === "number")
        data.requireApprovalAboveRisk = body.requireApprovalAboveRisk;
      if (Array.isArray(body.allowedAgentIds)) data.allowedAgentIds = body.allowedAgentIds;
      if (body.blocked !== undefined) data.blocked = body.blocked === true;
      if (body.metadata !== undefined) data.metadata = body.metadata;

      const updated = await storage.upsertAgentToolPolicy(data as Parameters<typeof storage.upsertAgentToolPolicy>[0]);
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update policy error", { error: String(error) });
      res.status(500).json({ message: "Failed to update policy" });
    }
  });

  // Trust Boundary Rules — persisted to DB
  app.get("/api/agent-tool-security/boundary-rules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const rules = await storage.getAgentTrustBoundaryRulesList(orgId);
      res.json(rules);
    } catch (error) {
      logger.child("routes").error("List boundary rules error", { error: String(error) });
      res.status(500).json({ message: "Failed to list boundary rules" });
    }
  });

  app.post("/api/agent-tool-security/boundary-rules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;
      if (!body.name || typeof body.name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!body.sourceBoundary || !VALID_BOUNDARIES.includes(body.sourceBoundary)) {
        return res.status(400).json({ message: `sourceBoundary must be one of: ${VALID_BOUNDARIES.join(", ")}` });
      }
      if (!body.targetBoundary || !VALID_BOUNDARIES.includes(body.targetBoundary)) {
        return res.status(400).json({ message: `targetBoundary must be one of: ${VALID_BOUNDARIES.join(", ")}` });
      }
      if (!body.action || !VALID_BOUNDARY_ACTIONS.includes(body.action)) {
        return res.status(400).json({ message: `action must be one of: ${VALID_BOUNDARY_ACTIONS.join(", ")}` });
      }
      const rule = await storage.createAgentTrustBoundaryRule({
        orgId,
        name: body.name,
        sourceBoundary: body.sourceBoundary,
        targetBoundary: body.targetBoundary,
        action: body.action,
        priority: typeof body.priority === "number" ? body.priority : 100,
        enabled: body.enabled !== false,
        metadata: {
          description: typeof body.description === "string" ? body.description : "",
          conditions: Array.isArray(body.conditions) ? body.conditions : [],
        },
      });
      res.status(201).json(rule);
    } catch (error) {
      logger.child("routes").error("Create boundary rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create boundary rule" });
    }
  });

  app.patch("/api/agent-tool-security/boundary-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const body = req.body;
      const updates: Record<string, unknown> = {};
      if (body.name !== undefined) {
        if (typeof body.name !== "string") return res.status(400).json({ message: "name must be a string" });
        updates.name = body.name;
      }
      if (body.action !== undefined) {
        if (!VALID_BOUNDARY_ACTIONS.includes(body.action))
          return res.status(400).json({ message: `action must be one of: ${VALID_BOUNDARY_ACTIONS.join(", ")}` });
        updates.action = body.action;
      }
      if (body.enabled !== undefined) {
        updates.enabled = body.enabled === true;
      }
      if (body.priority !== undefined) {
        if (typeof body.priority !== "number") return res.status(400).json({ message: "priority must be a number" });
        updates.priority = body.priority;
      }
      const updated = await storage.updateAgentTrustBoundaryRule(id, orgId, updates);
      if (!updated) return res.status(404).json({ message: "Boundary rule not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update boundary rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to update boundary rule" });
    }
  });

  app.delete("/api/agent-tool-security/boundary-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const deleted = await storage.deleteAgentTrustBoundaryRule(id, orgId);
      if (!deleted) return res.status(404).json({ message: "Boundary rule not found" });
      res.json({ message: "Boundary rule deleted" });
    } catch (error) {
      logger.child("routes").error("Delete boundary rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete boundary rule" });
    }
  });
}
