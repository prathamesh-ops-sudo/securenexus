import { describe, it, expect, vi, beforeEach } from "vitest";

// All vi.mock calls must use inline factories (no external references)
vi.mock("../storage", () => ({
  storage: {
    getAlert: vi.fn(),
    getJob: vi.fn(),
    createJob: vi.fn(),
    createAuditLog: vi.fn(),
    incrementUsage: vi.fn(),
  },
}));

vi.mock("../job-queue", () => ({
  enqueueJob: vi.fn(),
}));

vi.mock("../auth", () => ({
  isAuthenticated: (_req: any, _res: any, next: any) => next(),
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: (req: any, _res: any, next: any) => {
    req.orgId = "org-1";
    req.user = { id: "user-1", orgId: "org-1", firstName: "Test", lastName: "User" };
    next();
  },
  requireOrgId: (_req: any, _res: any, next: any) => next(),
  requireMinRole: () => (_req: any, _res: any, next: any) => next(),
}));

vi.mock("../middleware/plan-enforcement", () => ({
  enforcePlanLimit: () => (_req: any, _res: any, next: any) => next(),
}));

vi.mock("express-rate-limit", () => ({
  default: () => (_req: any, _res: any, next: any) => next(),
}));

vi.mock("../ai", () => ({
  triageAlert: vi.fn(),
  buildThreatIntelContext: vi.fn(),
  correlateAlerts: vi.fn(),
}));

vi.mock("../ai/fallback", () => ({
  withAiFallback: vi.fn(),
}));

vi.mock("../ai/decision-receipts", () => ({
  createDecisionReceipt: vi.fn().mockResolvedValue("decision-1"),
  finalizeDecisionReceipt: vi.fn().mockResolvedValue(undefined),
  persistDecisionEvidence: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../event-bus", () => ({
  broadcastEvent: vi.fn(),
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
  },
}));

vi.mock("../outbound-security", () => ({
  validateWebhookUrl: vi.fn(),
  isCircuitOpen: vi.fn(),
  isWebhookRateLimited: vi.fn(),
  recordDeliverySuccess: vi.fn(),
  recordDeliveryFailure: vi.fn(),
  secureOutboundFetch: vi.fn(),
  redactDeliveryLog: vi.fn(),
}));

vi.mock("../outbox-processor", () => ({
  createEventFingerprint: vi.fn(),
}));

vi.mock("../event-catalog", () => ({
  validateAndLogEvent: vi.fn(),
}));

vi.mock("../api-response", () => ({
  reply: vi.fn(),
  replyError: vi.fn(),
  replyUnauthenticated: vi.fn(),
  replyForbidden: vi.fn(),
  replyRateLimit: vi.fn(),
  ERROR_CODES: {},
}));

import express from "express";
import request from "supertest";
import { storage } from "../storage";
import { enqueueJob } from "../job-queue";
import { triageAlert, buildThreatIntelContext } from "../ai";
import { broadcastEvent } from "../event-bus";
import { createDecisionReceipt, finalizeDecisionReceipt, persistDecisionEvidence } from "../ai/decision-receipts";
import { registerAiTriageRoutes } from "../routes/ai/triage";

const mockStorage = storage as any;
const mockEnqueueJob = enqueueJob as any;
const mockTriageAlert = triageAlert as any;
const mockBuildThreatIntelContext = buildThreatIntelContext as any;
const mockBroadcastEvent = broadcastEvent as any;
const mockCreateDecisionReceipt = createDecisionReceipt as any;
const mockFinalizeDecisionReceipt = finalizeDecisionReceipt as any;

function createApp() {
  const app = express();
  app.use(express.json());
  registerAiTriageRoutes(app);
  return app;
}

describe("Async triage endpoint", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("POST /api/ai/triage/:alertId", () => {
    it("returns 202 with jobId and pollUrl", async () => {
      mockStorage.getAlert.mockResolvedValue({ id: "alert-1", orgId: "org-1", title: "Test alert" });
      mockEnqueueJob.mockResolvedValue({ id: "job-123", type: "ai_triage", status: "pending" });
      mockStorage.createAuditLog.mockResolvedValue({});
      mockStorage.incrementUsage.mockResolvedValue(undefined);

      const app = createApp();
      const res = await request(app).post("/api/ai/triage/alert-1").set("Content-Type", "application/json").send({});

      expect(res.status).toBe(202);
      expect(res.body).toHaveProperty("jobId", "job-123");
      expect(res.body).toHaveProperty("status", "accepted");
      expect(res.body).toHaveProperty("pollUrl", "/api/ai/triage/jobs/job-123");
    });

    it("returns 404 when alert not found", async () => {
      mockStorage.getAlert.mockResolvedValue(undefined);

      const app = createApp();
      const res = await request(app).post("/api/ai/triage/nonexistent").send({});

      expect(res.status).toBe(404);
    });

    it("returns 404 when alert belongs to different org", async () => {
      mockStorage.getAlert.mockResolvedValue({ id: "alert-1", orgId: "other-org", title: "Test" });

      const app = createApp();
      const res = await request(app).post("/api/ai/triage/alert-1").send({});

      expect(res.status).toBe(404);
    });
  });

  describe("GET /api/ai/triage/jobs/:jobId", () => {
    it("returns pending status for queued job", async () => {
      mockStorage.getJob.mockResolvedValue({ id: "job-1", orgId: "org-1", status: "pending" });

      const app = createApp();
      const res = await request(app).get("/api/ai/triage/jobs/job-1");

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "pending" });
    });

    it("returns completed status with result for finished job", async () => {
      const triageResult = { severity: "high", priority: 1, recommendation: "Investigate" };
      mockStorage.getJob.mockResolvedValue({
        id: "job-1",
        orgId: "org-1",
        status: "completed",
        result: { alertId: "alert-1", result: triageResult },
      });

      const app = createApp();
      const res = await request(app).get("/api/ai/triage/jobs/job-1");

      expect(res.status).toBe(200);
      expect(res.body.status).toBe("completed");
      expect(res.body.result).toEqual({ alertId: "alert-1", result: triageResult });
    });

    it("returns failed status with error for failed job", async () => {
      mockStorage.getJob.mockResolvedValue({
        id: "job-1",
        orgId: "org-1",
        status: "failed",
        lastError: "AI model error",
        error: undefined,
      });

      const app = createApp();
      const res = await request(app).get("/api/ai/triage/jobs/job-1");

      expect(res.status).toBe(200);
      expect(res.body.status).toBe("failed");
      expect(res.body.error).toBeDefined();
    });

    it("returns 404 for unknown job", async () => {
      mockStorage.getJob.mockResolvedValue(undefined);

      const app = createApp();
      const res = await request(app).get("/api/ai/triage/jobs/nonexistent");

      expect(res.status).toBe(404);
    });

    it("returns 404 when job belongs to different org", async () => {
      mockStorage.getJob.mockResolvedValue({ id: "job-1", orgId: "other-org", status: "pending" });

      const app = createApp();
      const res = await request(app).get("/api/ai/triage/jobs/job-1");

      expect(res.status).toBe(404);
    });
  });

  describe("ai_triage job handler", () => {
    it("calls triageAlert and returns result", async () => {
      const mockAlert = { id: "alert-1", orgId: "org-1", title: "Test" };
      const mockThreatCtx = { enrichmentResults: [], osintMatches: [] };
      const mockResult = { severity: "high", priority: 1 };

      mockStorage.getAlert.mockResolvedValue(mockAlert);
      mockTriageAlert.mockResolvedValue(mockResult);
      mockBuildThreatIntelContext.mockResolvedValue(mockThreatCtx);

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      const handler = getAiTriageHandler();

      const job = { id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } };
      const result = await handler(job);

      expect(mockStorage.getAlert).toHaveBeenCalledWith("alert-1");
      expect(mockBuildThreatIntelContext).toHaveBeenCalledWith([mockAlert]);
      expect(mockTriageAlert).toHaveBeenCalledWith(mockAlert, mockThreatCtx, "org-1", "decision-1");
      expect(result).toEqual({ alertId: "alert-1", decisionId: "decision-1", result: mockResult });
      expect(mockCreateDecisionReceipt).toHaveBeenCalledWith({
        orgId: "org-1",
        alertId: "alert-1",
        incidentId: undefined,
        tier: "tier3_assisted",
        autonomyMode: "observe_only",
      });
    });

    it("persists model confidence, measured latency, and derived outcome", async () => {
      const mockAlert = { id: "alert-1", orgId: "org-1", title: "Test" };
      const mockThreatCtx = { enrichmentResults: [], osintMatches: [] };
      const mockResult = {
        severity: "high",
        priority: 1,
        confidence: 0.91,
        falsePositiveLikelihood: 0.05,
        escalationRequired: true,
        reasoning: "Evidence supports escalation",
        recommendedAction: "Escalate",
      };

      mockStorage.getAlert.mockResolvedValue(mockAlert);
      mockTriageAlert.mockResolvedValue(mockResult);
      mockBuildThreatIntelContext.mockResolvedValue(mockThreatCtx);

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      await getAiTriageHandler()({ id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } });

      expect(mockFinalizeDecisionReceipt).toHaveBeenCalledWith(
        "org-1",
        "decision-1",
        expect.objectContaining({
          outcome: "escalate_human",
          confidenceScore: 0.91,
          status: "completed",
        }),
      );
      expect(mockFinalizeDecisionReceipt.mock.calls[0][2].timeToDecisionMs).toEqual(expect.any(Number));
      expect(mockFinalizeDecisionReceipt.mock.calls[0][2].timeToDecisionMs).toBeGreaterThanOrEqual(0);
    });

    it("keeps confidence null when the model does not return it", async () => {
      const mockAlert = { id: "alert-1", orgId: "org-1", title: "Test" };
      mockStorage.getAlert.mockResolvedValue(mockAlert);
      mockTriageAlert.mockResolvedValue({
        falsePositiveLikelihood: 0.95,
        escalationRequired: false,
        reasoning: "Likely benign",
        recommendedAction: "Close",
      });
      mockBuildThreatIntelContext.mockResolvedValue({ enrichmentResults: [], osintMatches: [] });

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      await getAiTriageHandler()({ id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } });

      expect(mockFinalizeDecisionReceipt.mock.calls[0][2]).toEqual(
        expect.objectContaining({ confidenceScore: null, outcome: "false_positive" }),
      );
    });

    it("persists a visible failed decision when schema validation fails", async () => {
      const mockAlert = { id: "alert-1", orgId: "org-1", title: "Test" };
      const failure = new Error("AI returned invalid schema");
      mockStorage.getAlert.mockResolvedValue(mockAlert);
      mockBuildThreatIntelContext.mockResolvedValue({ enrichmentResults: [], osintMatches: [] });
      mockTriageAlert.mockRejectedValue(failure);

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      const result = await getAiTriageHandler()({ id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } });

      expect(result).toEqual({ error: "AI returned invalid schema", alertId: "alert-1", decisionId: "decision-1" });
      expect(mockFinalizeDecisionReceipt).toHaveBeenCalledWith(
        "org-1",
        "decision-1",
        expect.objectContaining({
          outcome: null,
          confidenceScore: null,
          status: "failed",
          reasoning: "AI returned invalid schema",
          retrievalStatus: "empty",
        }),
      );
      expect(mockFinalizeDecisionReceipt.mock.calls[0][2].timeToDecisionMs).toEqual(expect.any(Number));
      expect(persistDecisionEvidence).toHaveBeenCalledWith("org-1", "decision-1", mockAlert, null);
    });

    it("broadcasts ai:triage_complete SSE event on success", async () => {
      const mockAlert = { id: "alert-1", orgId: "org-1", title: "Test" };
      const mockThreatCtx = { enrichmentResults: [], osintMatches: [] };
      const mockResult = { severity: "high", priority: 1 };

      mockStorage.getAlert.mockResolvedValue(mockAlert);
      mockTriageAlert.mockResolvedValue(mockResult);
      mockBuildThreatIntelContext.mockResolvedValue(mockThreatCtx);

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      const handler = getAiTriageHandler();

      const job = { id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } };
      await handler(job);

      expect(mockBroadcastEvent).toHaveBeenCalledWith({
        type: "ai:triage_complete",
        orgId: "org-1",
        data: { jobId: "job-1", alertId: "alert-1", result: mockResult },
      });
    });

    it("returns error result when alert not found", async () => {
      mockStorage.getAlert.mockResolvedValue(undefined);

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      const handler = getAiTriageHandler();

      const job = { id: "job-1", payload: { alertId: "alert-999", orgId: "org-1" } };
      const result = await handler(job);

      expect(result).toEqual({ error: "Alert not found", alertId: "alert-999" });
      expect(mockBroadcastEvent).not.toHaveBeenCalled();
    });

    it("preserves unavailable retrieval provenance in the completed result", async () => {
      const mockAlert = { id: "alert-1", orgId: "org-1", title: "Test" };
      const mockThreatCtx = { enrichmentResults: [], osintMatches: [], retrievalUnavailable: true };
      const mockResult = { severity: "high", priority: 1 };

      mockStorage.getAlert.mockResolvedValue(mockAlert);
      mockTriageAlert.mockResolvedValue(mockResult);
      mockBuildThreatIntelContext.mockResolvedValue(mockThreatCtx);

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      const handler = getAiTriageHandler();

      const result = await handler({ id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } });

      expect(result).toEqual({
        alertId: "alert-1",
        decisionId: "decision-1",
        result: { severity: "high", priority: 1, retrievalUnavailable: true },
      });
    });

    it("returns error result on triageAlert failure", async () => {
      mockStorage.getAlert.mockResolvedValue({ id: "alert-1", orgId: "org-1" });
      mockBuildThreatIntelContext.mockResolvedValue({ enrichmentResults: [], osintMatches: [] });
      mockTriageAlert.mockRejectedValue(new Error("AI model timeout"));

      const { getAiTriageHandler } = await import("../routes/ai/triage");
      const handler = getAiTriageHandler();

      const job = { id: "job-1", payload: { alertId: "alert-1", orgId: "org-1" } };
      const result = await handler(job);

      expect(result).toEqual({ error: "AI model timeout", alertId: "alert-1", decisionId: "decision-1" });
    });
  });
});
