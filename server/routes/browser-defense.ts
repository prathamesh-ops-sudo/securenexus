import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getBrowserDefenseStats,
  listSessions,
  getSessionById,
  isolateSession,
  terminateSession,
  listDomEvents,
  classifyDomAction,
  listEgressRules,
  createEgressRule,
  updateEgressRule,
  deleteEgressRule,
  listTrustedPaths,
  getTrustedPathById,
  createTrustedPath,
  updateTrustedPath,
  deleteTrustedPath,
  listInjectionPatterns,
  updateInjectionPattern,
  evaluateEgress,
  type SessionState,
  type ActionSeverity,
  type PolicyVerdict,
} from "../browser-defense-engine";

const VALID_SESSION_STATES: SessionState[] = ["active", "isolated", "terminated", "expired"];
const VALID_SEVERITIES: ActionSeverity[] = ["info", "low", "medium", "high", "critical"];
const VALID_VERDICTS: PolicyVerdict[] = ["allow", "block", "challenge", "log_only"];
const VALID_PROTOCOLS = ["https", "http", "wss", "ws", "any"] as const;
const VALID_DIRECTIONS = ["outbound", "inbound"] as const;

export function registerBrowserDefenseRoutes(app: Express): void {
  app.get("/api/browser-defense/stats", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(getBrowserDefenseStats(orgId));
    } catch (error) {
      logger.child("routes").error("Browser defense stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch browser defense stats" });
    }
  });

  app.get("/api/browser-defense/sessions", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const filters: { state?: SessionState; agentId?: string } = {};
      if (typeof req.query.state === "string" && VALID_SESSION_STATES.includes(req.query.state as SessionState))
        filters.state = req.query.state as SessionState;
      if (typeof req.query.agentId === "string") filters.agentId = req.query.agentId;
      res.json(listSessions(orgId, filters));
    } catch (error) {
      logger.child("routes").error("List sessions error", { error: String(error) });
      res.status(500).json({ message: "Failed to list browser sessions" });
    }
  });

  app.get("/api/browser-defense/sessions/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const session = getSessionById(orgId, id);
      if (!session) return res.status(404).json({ message: "Session not found" });
      res.json(session);
    } catch (error) {
      logger.child("routes").error("Get session error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch session" });
    }
  });

  app.post("/api/browser-defense/sessions/:id/isolate", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const session = isolateSession(orgId, id);
      if (!session) return res.status(404).json({ message: "Session not found" });
      res.json(session);
    } catch (error) {
      logger.child("routes").error("Isolate session error", { error: String(error) });
      res.status(500).json({ message: "Failed to isolate session" });
    }
  });

  app.post("/api/browser-defense/sessions/:id/terminate", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const session = terminateSession(orgId, id);
      if (!session) return res.status(404).json({ message: "Session not found" });
      res.json(session);
    } catch (error) {
      logger.child("routes").error("Terminate session error", { error: String(error) });
      res.status(500).json({ message: "Failed to terminate session" });
    }
  });

  app.get("/api/browser-defense/dom-events", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const filters: {
        sessionId?: string;
        classification?: string;
        severity?: ActionSeverity;
        verdict?: PolicyVerdict;
      } = {};
      if (typeof req.query.sessionId === "string") filters.sessionId = req.query.sessionId;
      if (typeof req.query.classification === "string") filters.classification = req.query.classification;
      if (typeof req.query.severity === "string" && VALID_SEVERITIES.includes(req.query.severity as ActionSeverity))
        filters.severity = req.query.severity as ActionSeverity;
      if (typeof req.query.verdict === "string" && VALID_VERDICTS.includes(req.query.verdict as PolicyVerdict))
        filters.verdict = req.query.verdict as PolicyVerdict;
      res.json(listDomEvents(orgId, filters));
    } catch (error) {
      logger.child("routes").error("List DOM events error", { error: String(error) });
      res.status(500).json({ message: "Failed to list DOM events" });
    }
  });

  app.post("/api/browser-defense/dom-events/classify", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;
      if (!body.sessionId || typeof body.sessionId !== "string") {
        return res.status(400).json({ message: "sessionId is required" });
      }
      if (!body.eventType || typeof body.eventType !== "string") {
        return res.status(400).json({ message: "eventType is required" });
      }
      if (!body.targetSelector || typeof body.targetSelector !== "string") {
        return res.status(400).json({ message: "targetSelector is required" });
      }
      if (!body.rawPayload || typeof body.rawPayload !== "string") {
        return res.status(400).json({ message: "rawPayload is required" });
      }
      const event = classifyDomAction(orgId, body.sessionId, {
        eventType: body.eventType,
        targetSelector: body.targetSelector,
        rawPayload: body.rawPayload,
      });
      res.status(201).json(event);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SESSION_NOT_FOUND")) return res.status(404).json({ message: "Session not found" });
      logger.child("routes").error("Classify DOM action error", { error: errMsg });
      res.status(500).json({ message: "Failed to classify DOM action" });
    }
  });

  app.get("/api/browser-defense/egress-rules", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(listEgressRules(orgId));
    } catch (error) {
      logger.child("routes").error("List egress rules error", { error: String(error) });
      res.status(500).json({ message: "Failed to list egress rules" });
    }
  });

  app.post("/api/browser-defense/egress-rules", isAuthenticated, async (req, res) => {
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
      if (!body.domainPattern || typeof body.domainPattern !== "string") {
        return res.status(400).json({ message: "domainPattern is required" });
      }
      if (!body.direction || !VALID_DIRECTIONS.includes(body.direction)) {
        return res.status(400).json({ message: `direction must be one of: ${VALID_DIRECTIONS.join(", ")}` });
      }
      if (!body.protocol || !VALID_PROTOCOLS.includes(body.protocol)) {
        return res.status(400).json({ message: `protocol must be one of: ${VALID_PROTOCOLS.join(", ")}` });
      }
      if (!body.action || !VALID_VERDICTS.includes(body.action)) {
        return res.status(400).json({ message: `action must be one of: ${VALID_VERDICTS.join(", ")}` });
      }
      const rule = createEgressRule(orgId, {
        name: body.name,
        description: typeof body.description === "string" ? body.description : "",
        direction: body.direction,
        domainPattern: body.domainPattern,
        portRange: typeof body.portRange === "string" ? body.portRange : "*",
        protocol: body.protocol,
        action: body.action,
      });
      res.status(201).json(rule);
    } catch (error) {
      logger.child("routes").error("Create egress rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create egress rule" });
    }
  });

  app.patch("/api/browser-defense/egress-rules/:id", isAuthenticated, async (req, res) => {
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
      if (body.description !== undefined)
        sanitized.description = typeof body.description === "string" ? body.description : "";
      if (body.domainPattern !== undefined) {
        if (typeof body.domainPattern !== "string")
          return res.status(400).json({ message: "domainPattern must be a string" });
        sanitized.domainPattern = body.domainPattern;
      }
      if (body.portRange !== undefined) sanitized.portRange = typeof body.portRange === "string" ? body.portRange : "*";
      if (body.protocol !== undefined) {
        if (!VALID_PROTOCOLS.includes(body.protocol))
          return res.status(400).json({ message: `protocol must be one of: ${VALID_PROTOCOLS.join(", ")}` });
        sanitized.protocol = body.protocol;
      }
      if (body.action !== undefined) {
        if (!VALID_VERDICTS.includes(body.action))
          return res.status(400).json({ message: `action must be one of: ${VALID_VERDICTS.join(", ")}` });
        sanitized.action = body.action;
      }
      if (body.enabled !== undefined) sanitized.enabled = body.enabled === true;
      const updated = updateEgressRule(orgId, id, sanitized as Parameters<typeof updateEgressRule>[2]);
      if (!updated) return res.status(404).json({ message: "Egress rule not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update egress rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to update egress rule" });
    }
  });

  app.delete("/api/browser-defense/egress-rules/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const deleted = deleteEgressRule(orgId, id);
      if (!deleted) return res.status(404).json({ message: "Egress rule not found" });
      res.json({ message: "Egress rule deleted" });
    } catch (error) {
      logger.child("routes").error("Delete egress rule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete egress rule" });
    }
  });

  app.get("/api/browser-defense/trusted-paths", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(listTrustedPaths(orgId));
    } catch (error) {
      logger.child("routes").error("List trusted paths error", { error: String(error) });
      res.status(500).json({ message: "Failed to list trusted paths" });
    }
  });

  app.get("/api/browser-defense/trusted-paths/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const path = getTrustedPathById(orgId, id);
      if (!path) return res.status(404).json({ message: "Trusted path not found" });
      res.json(path);
    } catch (error) {
      logger.child("routes").error("Get trusted path error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch trusted path" });
    }
  });

  app.post("/api/browser-defense/trusted-paths", isAuthenticated, async (req, res) => {
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
      if (!Array.isArray(body.steps) || body.steps.length === 0) {
        return res.status(400).json({ message: "steps must be a non-empty array" });
      }
      if (!body.failAction || !VALID_VERDICTS.includes(body.failAction)) {
        return res.status(400).json({ message: `failAction must be one of: ${VALID_VERDICTS.join(", ")}` });
      }
      const path = createTrustedPath(orgId, {
        name: body.name,
        description: typeof body.description === "string" ? body.description : "",
        steps: body.steps,
        enforceOrder: body.enforceOrder === true,
        maxDurationMs: typeof body.maxDurationMs === "number" && body.maxDurationMs > 0 ? body.maxDurationMs : 60000,
        failAction: body.failAction,
      });
      res.status(201).json(path);
    } catch (error) {
      logger.child("routes").error("Create trusted path error", { error: String(error) });
      res.status(500).json({ message: "Failed to create trusted path" });
    }
  });

  app.patch("/api/browser-defense/trusted-paths/:id", isAuthenticated, async (req, res) => {
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
      if (body.description !== undefined)
        sanitized.description = typeof body.description === "string" ? body.description : "";
      if (body.enforceOrder !== undefined) sanitized.enforceOrder = body.enforceOrder === true;
      if (body.maxDurationMs !== undefined) {
        if (typeof body.maxDurationMs !== "number" || body.maxDurationMs < 1)
          return res.status(400).json({ message: "maxDurationMs must be a positive number" });
        sanitized.maxDurationMs = body.maxDurationMs;
      }
      if (body.failAction !== undefined) {
        if (!VALID_VERDICTS.includes(body.failAction))
          return res.status(400).json({ message: `failAction must be one of: ${VALID_VERDICTS.join(", ")}` });
        sanitized.failAction = body.failAction;
      }
      if (body.enabled !== undefined) sanitized.enabled = body.enabled === true;
      const updated = updateTrustedPath(orgId, id, sanitized as Parameters<typeof updateTrustedPath>[2]);
      if (!updated) return res.status(404).json({ message: "Trusted path not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update trusted path error", { error: String(error) });
      res.status(500).json({ message: "Failed to update trusted path" });
    }
  });

  app.delete("/api/browser-defense/trusted-paths/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const deleted = deleteTrustedPath(orgId, id);
      if (!deleted) return res.status(404).json({ message: "Trusted path not found" });
      res.json({ message: "Trusted path deleted" });
    } catch (error) {
      logger.child("routes").error("Delete trusted path error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete trusted path" });
    }
  });

  app.get("/api/browser-defense/injection-patterns", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      res.json(listInjectionPatterns(orgId));
    } catch (error) {
      logger.child("routes").error("List injection patterns error", { error: String(error) });
      res.status(500).json({ message: "Failed to list injection patterns" });
    }
  });

  app.patch("/api/browser-defense/injection-patterns/:id", isAuthenticated, async (req, res) => {
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
      if (body.severity !== undefined) {
        if (!VALID_SEVERITIES.includes(body.severity))
          return res.status(400).json({ message: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` });
        sanitized.severity = body.severity;
      }
      if (body.action !== undefined) {
        if (!VALID_VERDICTS.includes(body.action))
          return res.status(400).json({ message: `action must be one of: ${VALID_VERDICTS.join(", ")}` });
        sanitized.action = body.action;
      }
      if (body.enabled !== undefined) sanitized.enabled = body.enabled === true;
      const updated = updateInjectionPattern(orgId, id, sanitized as Parameters<typeof updateInjectionPattern>[2]);
      if (!updated) return res.status(404).json({ message: "Injection pattern not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update injection pattern error", { error: String(error) });
      res.status(500).json({ message: "Failed to update injection pattern" });
    }
  });

  app.post("/api/browser-defense/evaluate-egress", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;
      if (!body.destination || typeof body.destination !== "string") {
        return res.status(400).json({ message: "destination is required" });
      }
      if (!body.protocol || typeof body.protocol !== "string") {
        return res.status(400).json({ message: "protocol is required" });
      }
      const result = evaluateEgress(orgId, body.destination, body.protocol);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Evaluate egress error", { error: String(error) });
      res.status(500).json({ message: "Failed to evaluate egress" });
    }
  });
}
