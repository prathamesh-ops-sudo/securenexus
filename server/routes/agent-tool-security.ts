import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getToolCatalog,
  getToolById,
  verifyTool,
  getToolInvocations,
  getInvocationById,
  recordInvocation,
  getAnomalyDetections,
  acknowledgeAnomaly,
  getToolPolicies,
  updateToolPolicy,
  getTrustBoundaryRules,
  createBoundaryRule,
  updateBoundaryRule,
  deleteBoundaryRule,
  getAgentToolStats,
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
const VALID_RATE_PERIODS = ["minute", "hour", "day"] as const;

export function registerAgentToolSecurityRoutes(app: Express): void {
  app.get("/api/agent-tool-security/stats", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(getAgentToolStats(orgId));
    } catch (error) {
      logger.child("routes").error("Agent tool stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch agent tool security stats" });
    }
  });

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

  app.get("/api/agent-tool-security/invocations", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const filters: {
        toolId?: string;
        agentId?: string;
        verdict?: InvocationVerdict;
        chainId?: string;
      } = {};
      if (typeof req.query.toolId === "string") filters.toolId = req.query.toolId;
      if (typeof req.query.agentId === "string") filters.agentId = req.query.agentId;
      if (typeof req.query.verdict === "string" && VALID_VERDICTS.includes(req.query.verdict as InvocationVerdict))
        filters.verdict = req.query.verdict as InvocationVerdict;
      if (typeof req.query.chainId === "string") filters.chainId = req.query.chainId;
      res.json(getToolInvocations(orgId, filters));
    } catch (error) {
      logger.child("routes").error("List invocations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list invocations" });
    }
  });

  app.get("/api/agent-tool-security/invocations/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const inv = getInvocationById(orgId, id);
      if (!inv) return res.status(404).json({ message: "Invocation not found" });
      res.json(inv);
    } catch (error) {
      logger.child("routes").error("Get invocation error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch invocation" });
    }
  });

  app.post("/api/agent-tool-security/invocations", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;
      if (!body.agentId || typeof body.agentId !== "string") {
        return res.status(400).json({ message: "agentId is required" });
      }
      if (!body.agentName || typeof body.agentName !== "string") {
        return res.status(400).json({ message: "agentName is required" });
      }
      if (!body.toolId || typeof body.toolId !== "string") {
        return res.status(400).json({ message: "toolId is required" });
      }
      if (!Array.isArray(body.scopes) || body.scopes.length === 0) {
        return res.status(400).json({ message: "scopes must be a non-empty array" });
      }
      if (!body.input || typeof body.input !== "string") {
        return res.status(400).json({ message: "input is required" });
      }
      const invocation = recordInvocation(orgId, {
        agentId: body.agentId,
        agentName: body.agentName,
        toolId: body.toolId,
        scopes: body.scopes,
        destination: typeof body.destination === "string" ? body.destination : undefined,
        input: body.input,
        chainId: typeof body.chainId === "string" ? body.chainId : undefined,
        parentInvocationId: typeof body.parentInvocationId === "string" ? body.parentInvocationId : undefined,
      });
      res.status(201).json(invocation);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("TOOL_NOT_FOUND")) return res.status(404).json({ message: "Tool not found" });
      if (errMsg.includes("TOOL_DISABLED")) return res.status(400).json({ message: "Tool is disabled" });
      logger.child("routes").error("Record invocation error", { error: errMsg });
      res.status(500).json({ message: "Failed to record invocation" });
    }
  });

  app.get("/api/agent-tool-security/anomalies", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const filters: {
        type?: AnomalyType;
        severity?: ToolRiskLevel;
        acknowledged?: boolean;
      } = {};
      if (typeof req.query.type === "string" && VALID_ANOMALY_TYPES.includes(req.query.type as AnomalyType))
        filters.type = req.query.type as AnomalyType;
      if (typeof req.query.severity === "string" && VALID_RISK_LEVELS.includes(req.query.severity as ToolRiskLevel))
        filters.severity = req.query.severity as ToolRiskLevel;
      if (req.query.acknowledged === "true") filters.acknowledged = true;
      if (req.query.acknowledged === "false") filters.acknowledged = false;
      res.json(getAnomalyDetections(orgId, filters));
    } catch (error) {
      logger.child("routes").error("List anomalies error", { error: String(error) });
      res.status(500).json({ message: "Failed to list anomalies" });
    }
  });

  app.post("/api/agent-tool-security/anomalies/:id/acknowledge", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const result = acknowledgeAnomaly(orgId, id);
      if (!result) return res.status(404).json({ message: "Anomaly not found" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Acknowledge anomaly error", { error: String(error) });
      res.status(500).json({ message: "Failed to acknowledge anomaly" });
    }
  });

  app.get("/api/agent-tool-security/policies", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(getToolPolicies(orgId));
    } catch (error) {
      logger.child("routes").error("List policies error", { error: String(error) });
      res.status(500).json({ message: "Failed to list policies" });
    }
  });

  app.patch("/api/agent-tool-security/policies/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const body = req.body;
      const sanitized: Record<string, unknown> = {};
      if (body.maxRate !== undefined) {
        if (typeof body.maxRate !== "number" || body.maxRate < 1)
          return res.status(400).json({ message: "maxRate must be a positive number" });
        sanitized.maxRate = body.maxRate;
      }
      if (body.ratePeriod !== undefined) {
        if (!VALID_RATE_PERIODS.includes(body.ratePeriod))
          return res.status(400).json({ message: `ratePeriod must be one of: ${VALID_RATE_PERIODS.join(", ")}` });
        sanitized.ratePeriod = body.ratePeriod;
      }
      if (body.allowedScopes !== undefined) {
        if (!Array.isArray(body.allowedScopes))
          return res.status(400).json({ message: "allowedScopes must be an array" });
        sanitized.allowedScopes = body.allowedScopes;
      }
      if (body.blockedDestinations !== undefined) {
        if (!Array.isArray(body.blockedDestinations))
          return res.status(400).json({ message: "blockedDestinations must be an array" });
        sanitized.blockedDestinations = body.blockedDestinations;
      }
      if (body.requireAttestation !== undefined) {
        sanitized.requireAttestation = body.requireAttestation === true;
      }
      if (body.autoApproveBelow !== undefined) {
        if (!VALID_RISK_LEVELS.includes(body.autoApproveBelow))
          return res.status(400).json({ message: `autoApproveBelow must be one of: ${VALID_RISK_LEVELS.join(", ")}` });
        sanitized.autoApproveBelow = body.autoApproveBelow;
      }
      if (body.enabled !== undefined) {
        sanitized.enabled = body.enabled === true;
      }
      const updated = updateToolPolicy(orgId, id, sanitized as any);
      if (!updated) return res.status(404).json({ message: "Policy not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update policy error", { error: String(error) });
      res.status(500).json({ message: "Failed to update policy" });
    }
  });

  app.get("/api/agent-tool-security/boundary-rules", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(getTrustBoundaryRules(orgId));
    } catch (error) {
      logger.child("routes").error("List boundary rules error", { error: String(error) });
      res.status(500).json({ message: "Failed to list boundary rules" });
    }
  });

  app.post("/api/agent-tool-security/boundary-rules", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
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
      const rule = createBoundaryRule(orgId, {
        name: body.name,
        description: typeof body.description === "string" ? body.description : "",
        sourceBoundary: body.sourceBoundary,
        targetBoundary: body.targetBoundary,
        action: body.action,
        conditions: Array.isArray(body.conditions) ? body.conditions : [],
      });
      res.status(201).json(rule);
    } catch (error) {
      logger.child("routes").error("Create boundary rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create boundary rule" });
    }
  });

  app.patch("/api/agent-tool-security/boundary-rules/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const body = req.body;
      const sanitized: Record<string, unknown> = {};
      if (body.name !== undefined) {
        if (typeof body.name !== "string") return res.status(400).json({ message: "name must be a string" });
        sanitized.name = body.name;
      }
      if (body.description !== undefined) {
        sanitized.description = typeof body.description === "string" ? body.description : "";
      }
      if (body.action !== undefined) {
        if (!VALID_BOUNDARY_ACTIONS.includes(body.action))
          return res.status(400).json({ message: `action must be one of: ${VALID_BOUNDARY_ACTIONS.join(", ")}` });
        sanitized.action = body.action;
      }
      if (body.conditions !== undefined) {
        if (!Array.isArray(body.conditions)) return res.status(400).json({ message: "conditions must be an array" });
        sanitized.conditions = body.conditions;
      }
      if (body.enabled !== undefined) {
        sanitized.enabled = body.enabled === true;
      }
      const updated = updateBoundaryRule(orgId, id, sanitized as any);
      if (!updated) return res.status(404).json({ message: "Boundary rule not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update boundary rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to update boundary rule" });
    }
  });

  app.delete("/api/agent-tool-security/boundary-rules/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const deleted = deleteBoundaryRule(orgId, id);
      if (!deleted) return res.status(404).json({ message: "Boundary rule not found" });
      res.json({ message: "Boundary rule deleted" });
    } catch (error) {
      logger.child("routes").error("Delete boundary rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete boundary rule" });
    }
  });
}
