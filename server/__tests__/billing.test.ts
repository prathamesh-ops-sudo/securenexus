/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import type { Express } from "express";
import request from "supertest";

// ---------- mocks ----------

vi.mock("../stripe-service", () => ({
  isStripeEnabled: vi.fn().mockReturnValue(true),
  createCheckoutSession: vi.fn().mockResolvedValue({ url: "https://checkout.stripe.com/session_123" }),
  createPortalSession: vi.fn().mockResolvedValue({ url: "https://billing.stripe.com/portal_123" }),
  changePlan: vi.fn().mockResolvedValue(true),
  cancelSubscription: vi.fn().mockResolvedValue(true),
  reactivateSubscription: vi.fn().mockResolvedValue(true),
  handleWebhookEvent: vi.fn().mockResolvedValue(undefined),
  getUsageVsLimits: vi.fn().mockResolvedValue({
    plan: { name: "pro", displayName: "Pro", tier: "pro" },
    usage: {
      users: { current: 5, limit: 50, pct: 10, status: "ok" },
      dataSources: { current: 2, limit: 20, pct: 10, status: "ok" },
    },
  }),
}));

vi.mock("../tiered-packaging-engine", () => ({
  getAllPlanTiers: vi.fn().mockReturnValue([
    {
      id: "plan-free",
      name: "free",
      displayName: "Free",
      description: "Starter plan",
      monthlyPriceCents: 0,
      annualPriceCents: 0,
      currency: "usd",
      limits: { users: 5 },
      features: ["Basic dashboard"],
      recommended: false,
      badge: null,
      onboardingFeeCents: 0,
      supportHours: null,
      targetSegment: null,
    },
  ]),
  getAllAddOnModules: vi.fn().mockReturnValue([
    { id: "addon-1", name: "Advanced Threat Intel", description: "Premium feeds", annualPriceCents: 50000, currency: "usd", pricingModel: "annual", bestFor: ["enterprise"] },
  ]),
}));

vi.mock("../storage", () => ({
  storage: {
    createAuditLog: vi.fn().mockResolvedValue({}),
    getSubscription: vi.fn().mockResolvedValue(null),
    getPlanByName: vi.fn().mockResolvedValue({ name: "free", displayName: "Free", monthlyPriceCents: 0 }),
    getPlan: vi.fn().mockResolvedValue(null),
    getInvoices: vi.fn().mockResolvedValue([]),
    getAuditLogs: vi.fn().mockResolvedValue([
      { action: "billing_checkout_started", resourceType: "billing", details: {} },
      { action: "user_login", resourceType: "auth", details: {} },
      { action: "billing_plan_changed", resourceType: "billing", details: {} },
    ]),
  },
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../auth", () => ({
  isAuthenticated: (_req: any, _res: any, next: any) => {
    _req.user = { id: "user-1", email: "admin@test.com" };
    next();
  },
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: (req: any, _res: any, next: any) => {
    req.orgId = req.headers["x-org-id"] || "org-1";
    next();
  },
  requireOrgId: (req: any, res: any, next: any) => {
    if (!req.orgId) {
      return res.status(400).json({ data: null, errors: [{ code: "ORG_REQUIRED" }] });
    }
    next();
  },
  requireMinRole: (role: string) => (req: any, res: any, next: any) => {
    const userRole = req.headers["x-test-role"] || "admin";
    const hierarchy = ["read_only", "analyst", "admin", "owner"];
    if (hierarchy.indexOf(userRole) < hierarchy.indexOf(role)) {
      return res.status(403).json({ data: null, errors: [{ code: "FORBIDDEN", message: `Requires ${role}` }] });
    }
    next();
  },
}));

// ---------- imports after mocks ----------

import { registerBillingRoutes } from "../routes/billing";
import { storage } from "../storage";
import {
  isStripeEnabled,
  createCheckoutSession,
  cancelSubscription,
  reactivateSubscription,
  getUsageVsLimits,
  handleWebhookEvent,
} from "../stripe-service";

const mockStorage = storage as any;
const mockIsStripeEnabled = isStripeEnabled as any;
const mockCreateCheckoutSession = createCheckoutSession as any;
const mockCancelSubscription = cancelSubscription as any;
const mockReactivateSubscription = reactivateSubscription as any;
const mockGetUsageVsLimits = getUsageVsLimits as any;
const mockHandleWebhookEvent = handleWebhookEvent as any;

// ---------- helpers ----------

function createApp(): Express {
  const app = express();
  app.use(express.json());
  // Add rawBody for webhook endpoint
  app.use((req: any, _res, next) => {
    if (req.path === "/api/billing/webhook") {
      req.rawBody = Buffer.from(JSON.stringify(req.body));
    }
    next();
  });
  registerBillingRoutes(app);
  return app;
}

// ---------- tests ----------

describe("Billing Routes", () => {
  let app: Express;

  beforeEach(() => {
    vi.clearAllMocks();
    mockIsStripeEnabled.mockReturnValue(true);
    app = createApp();
  });

  describe("GET /api/billing/plans", () => {
    it("returns plan list", async () => {
      const res = await request(app).get("/api/billing/plans");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].name).toBe("free");
    });
  });

  describe("POST /api/billing/checkout-session", () => {
    it("returns 503 when Stripe is disabled", async () => {
      mockIsStripeEnabled.mockReturnValue(false);
      const res = await request(app)
        .post("/api/billing/checkout-session")
        .send({ planId: "pro", successUrl: "http://localhost/ok", cancelUrl: "http://localhost/cancel" });
      expect(res.status).toBe(503);
      expect(res.body.errors[0].code).toBe("STRIPE_DISABLED");
    });

    it("returns 400 when required fields are missing", async () => {
      const res = await request(app).post("/api/billing/checkout-session").send({});
      expect(res.status).toBe(400);
      expect(res.body.errors[0].code).toBe("MISSING_FIELDS");
    });

    it("delegates to createCheckoutSession with correct params", async () => {
      const res = await request(app)
        .post("/api/billing/checkout-session")
        .send({ planId: "pro", billingCycle: "annual", successUrl: "http://ok", cancelUrl: "http://cancel" });
      expect(res.status).toBe(200);
      expect(mockCreateCheckoutSession).toHaveBeenCalledWith(
        expect.objectContaining({
          orgId: "org-1",
          planId: "pro",
          billingCycle: "annual",
          successUrl: "http://ok",
          cancelUrl: "http://cancel",
          customerEmail: "admin@test.com",
        }),
      );
    });

    it("creates audit log entry for billing_checkout_started", async () => {
      await request(app)
        .post("/api/billing/checkout-session")
        .send({ planId: "pro", successUrl: "http://ok", cancelUrl: "http://cancel" });
      expect(mockStorage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "billing_checkout_started",
          resourceType: "billing",
          orgId: "org-1",
        }),
      );
    });
  });

  describe("POST /api/billing/cancel", () => {
    it("delegates to cancelSubscription with reason and immediate flag", async () => {
      const res = await request(app)
        .post("/api/billing/cancel")
        .send({ reason: "too_expensive", immediate: true });
      expect(res.status).toBe(200);
      expect(mockCancelSubscription).toHaveBeenCalledWith(
        expect.objectContaining({
          orgId: "org-1",
          reason: "too_expensive",
          immediate: true,
        }),
      );
    });
  });

  describe("POST /api/billing/reactivate", () => {
    it("delegates to reactivateSubscription", async () => {
      const res = await request(app).post("/api/billing/reactivate").send({});
      expect(res.status).toBe(200);
      expect(mockReactivateSubscription).toHaveBeenCalledWith(
        expect.objectContaining({ orgId: "org-1" }),
      );
    });
  });

  describe("GET /api/billing/usage-vs-limits", () => {
    it("returns plan and usage data structure", async () => {
      const res = await request(app).get("/api/billing/usage-vs-limits");
      expect(res.status).toBe(200);
      expect(res.body.data.plan).toEqual({ name: "pro", displayName: "Pro", tier: "pro" });
      expect(res.body.data.usage.users).toEqual({ current: 5, limit: 50, pct: 10, status: "ok" });
    });
  });

  describe("GET /api/billing/invoices", () => {
    it("returns invoice list for org", async () => {
      mockStorage.getInvoices.mockResolvedValue([{ id: "inv-1", amountDueCents: 5000 }]);
      const res = await request(app).get("/api/billing/invoices");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(mockStorage.getInvoices).toHaveBeenCalledWith("org-1", 50);
    });
  });

  describe("GET /api/billing/activity", () => {
    it("filters audit logs to billing-related actions", async () => {
      const res = await request(app).get("/api/billing/activity");
      expect(res.status).toBe(200);
      // Should filter out user_login (non-billing) and keep 2 billing entries
      expect(res.body.data).toHaveLength(2);
    });
  });

  describe("Billing mutation routes require admin role", () => {
    const mutationRoutes = [
      { method: "post", path: "/api/billing/checkout-session", body: { planId: "pro", successUrl: "x", cancelUrl: "y" } },
      { method: "post", path: "/api/billing/portal-session", body: { returnUrl: "x" } },
      { method: "post", path: "/api/billing/change-plan", body: { newPlanId: "pro" } },
      { method: "post", path: "/api/billing/cancel", body: {} },
      { method: "post", path: "/api/billing/reactivate", body: {} },
    ];

    for (const route of mutationRoutes) {
      it(`${route.method.toUpperCase()} ${route.path} rejects analyst role`, async () => {
        const res = await (request(app) as any)
          [route.method](route.path)
          .set("X-Test-Role", "analyst")
          .send(route.body);
        expect(res.status).toBe(403);
      });
    }
  });

  describe("POST /api/billing/webhook", () => {
    it("returns 400 when stripe-signature header is missing", async () => {
      const res = await request(app).post("/api/billing/webhook").send({});
      expect(res.status).toBe(400);
      expect(res.body.error).toContain("Missing stripe-signature");
    });

    it("calls handleWebhookEvent with rawBody and signature", async () => {
      const res = await request(app)
        .post("/api/billing/webhook")
        .set("stripe-signature", "sig_test_123")
        .send({ type: "checkout.session.completed" });
      expect(res.status).toBe(200);
      expect(mockHandleWebhookEvent).toHaveBeenCalledWith(
        expect.any(Buffer),
        "sig_test_123",
      );
    });

    it("returns 400 when handleWebhookEvent throws", async () => {
      mockHandleWebhookEvent.mockRejectedValueOnce(new Error("Invalid signature"));
      const res = await request(app)
        .post("/api/billing/webhook")
        .set("stripe-signature", "bad_sig")
        .send({ type: "test" });
      expect(res.status).toBe(400);
      expect(res.body.error).toContain("Webhook verification failed");
    });
  });
});
