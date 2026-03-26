/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------- Stripe SDK mock ----------
const mockConstructEvent = vi.fn();
const mockCheckoutSessionsCreate = vi.fn();
const mockBillingPortalSessionsCreate = vi.fn();
const mockSubscriptionsUpdate = vi.fn();
const mockSubscriptionsCancel = vi.fn();
const mockSubscriptionsRetrieve = vi.fn();

function createStripeMockInstance() {
  return {
    webhooks: { constructEvent: mockConstructEvent },
    checkout: { sessions: { create: mockCheckoutSessionsCreate } },
    billingPortal: { sessions: { create: mockBillingPortalSessionsCreate } },
    subscriptions: {
      update: mockSubscriptionsUpdate,
      cancel: mockSubscriptionsCancel,
      retrieve: mockSubscriptionsRetrieve,
    },
  };
}

vi.mock("stripe", () => {
  function StripeMock() {
    return createStripeMockInstance();
  }
  StripeMock.prototype = {};
  return { default: StripeMock, __esModule: true };
});

// ---------- dependency mocks ----------
vi.mock("../storage", () => ({
  storage: {
    getSubscription: vi.fn().mockResolvedValue(null),
    getSubscriptionByStripeCustomerId: vi.fn().mockResolvedValue(null),
    getSubscriptionByStripeSubId: vi.fn().mockResolvedValue(null),
    createSubscription: vi.fn().mockResolvedValue({}),
    updateSubscription: vi.fn().mockResolvedValue({}),
    getPlan: vi.fn().mockResolvedValue(null),
    getPlanByName: vi.fn().mockResolvedValue(null),
    getInvoiceByStripeId: vi.fn().mockResolvedValue(null),
    createInvoice: vi.fn().mockResolvedValue({}),
    updateInvoice: vi.fn().mockResolvedValue({}),
    getOrgMemberships: vi.fn().mockResolvedValue([]),
    getOrganization: vi.fn().mockResolvedValue(null),
    getUsageRecords: vi.fn().mockResolvedValue([]),
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

vi.mock("../config", () => ({
  config: { databaseUrl: "postgresql://localhost/test", nodeEnv: "test" },
}));

vi.mock("../auth/storage", () => ({
  authStorage: { getUser: vi.fn().mockResolvedValue(null) },
}));

vi.mock("../email-service", () => ({
  sendEmail: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../email-templates", () => ({
  paymentFailedEmail: vi.fn().mockReturnValue({ subject: "Payment Failed", html: "<p>fail</p>", text: "fail" }),
  trialEndingEmail: vi.fn().mockReturnValue({ subject: "Trial Ending", html: "<p>trial</p>", text: "trial" }),
  subscriptionCancelledEmail: vi.fn().mockReturnValue({ subject: "Cancelled", html: "<p>cancel</p>", text: "cancel" }),
}));

vi.mock("../middleware/plan-enforcement", () => ({
  getUsageSummary: vi.fn().mockResolvedValue({
    tier: "pro",
    metrics: {
      users: { current: 5, limit: 50, pct: 10, status: "ok" },
      dataSources: { current: 2, limit: 20, pct: 10, status: "ok" },
    },
  }),
}));

// ---------- imports after mocks ----------
import { storage } from "../storage";

const mockStorage = storage as any;

describe("Stripe Service", () => {
  const savedKey = process.env.STRIPE_SECRET_KEY;
  const savedWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.STRIPE_SECRET_KEY = "sk_test_mock_key";
    process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_mock_secret";
  });

  afterEach(() => {
    if (savedKey !== undefined) process.env.STRIPE_SECRET_KEY = savedKey;
    else delete process.env.STRIPE_SECRET_KEY;
    if (savedWebhookSecret !== undefined) process.env.STRIPE_WEBHOOK_SECRET = savedWebhookSecret;
    else delete process.env.STRIPE_WEBHOOK_SECRET;
  });

  describe("isStripeEnabled", () => {
    it("returns true when STRIPE_SECRET_KEY is set", async () => {
      vi.resetModules();
      process.env.STRIPE_SECRET_KEY = "sk_test_key";
      const mod = await import("../stripe-service");
      expect(mod.isStripeEnabled()).toBe(true);
    });

    it("returns false when STRIPE_SECRET_KEY is not set", async () => {
      vi.resetModules();
      delete process.env.STRIPE_SECRET_KEY;
      const mod = await import("../stripe-service");
      expect(mod.isStripeEnabled()).toBe(false);
    });
  });

  describe("handleWebhookEvent", () => {
    // Each test uses resetModules to get a fresh stripe client cache
    async function importFresh() {
      vi.resetModules();
      process.env.STRIPE_SECRET_KEY = "sk_test_key";
      process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_secret";
      return await import("../stripe-service");
    }

    it("throws when Stripe client is null (STRIPE_SECRET_KEY not set)", async () => {
      vi.resetModules();
      delete process.env.STRIPE_SECRET_KEY;
      const mod = await import("../stripe-service");
      await expect(mod.handleWebhookEvent(Buffer.from("{}"), "sig")).rejects.toThrow("Stripe not configured");
    });

    it("throws when STRIPE_WEBHOOK_SECRET is not set", async () => {
      vi.resetModules();
      process.env.STRIPE_SECRET_KEY = "sk_test_key";
      delete process.env.STRIPE_WEBHOOK_SECRET;
      const mod = await import("../stripe-service");
      await expect(mod.handleWebhookEvent(Buffer.from("{}"), "sig")).rejects.toThrow(
        "STRIPE_WEBHOOK_SECRET not configured",
      );
    });

    it("calls constructEvent with correct params", async () => {
      const mod = await importFresh();
      const rawBody = Buffer.from('{"type":"test"}');
      const signature = "sig_test_123";
      mockConstructEvent.mockReturnValue({ type: "unknown.event", id: "evt_1", data: { object: {} } });

      await mod.handleWebhookEvent(rawBody, signature);

      expect(mockConstructEvent).toHaveBeenCalledWith(rawBody, signature, "whsec_test_secret");
    });

    it("routes checkout.session.completed to subscription creation logic", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "checkout.session.completed",
        id: "evt_checkout",
        data: {
          object: {
            id: "cs_123",
            metadata: { orgId: "org-1", planId: "plan-1", billingCycle: "monthly" },
            customer: "cus_123",
            subscription: "sub_123",
          },
        },
      });
      mockStorage.getSubscription.mockResolvedValue(null);

      await mod.handleWebhookEvent(Buffer.from("{}"), "sig");

      expect(mockStorage.createSubscription).toHaveBeenCalledWith(
        expect.objectContaining({
          orgId: "org-1",
          planId: "plan-1",
          billingCycle: "monthly",
          status: "active",
          stripeCustomerId: "cus_123",
          stripeSubscriptionId: "sub_123",
        }),
      );
    });

    it("routes invoice.paid to invoice recording logic", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "invoice.paid",
        id: "evt_inv_paid",
        data: {
          object: {
            id: "in_123",
            customer: "cus_123",
            amount_due: 5000,
            amount_paid: 5000,
            currency: "usd",
            invoice_pdf: "https://stripe.com/pdf",
            hosted_invoice_url: "https://stripe.com/hosted",
            period_start: 1700000000,
            period_end: 1702600000,
          },
        },
      });
      mockStorage.getSubscriptionByStripeCustomerId.mockResolvedValue({
        id: "sub-local-1",
        orgId: "org-1",
        status: "active",
      });
      mockStorage.getInvoiceByStripeId.mockResolvedValue(null);

      await mod.handleWebhookEvent(Buffer.from("{}"), "sig");

      expect(mockStorage.createInvoice).toHaveBeenCalledWith(
        expect.objectContaining({
          orgId: "org-1",
          stripeInvoiceId: "in_123",
          amountDueCents: 5000,
          amountPaidCents: 5000,
          status: "paid",
        }),
      );
    });

    it("routes invoice.payment_failed to payment failure handling", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "invoice.payment_failed",
        id: "evt_inv_fail",
        data: {
          object: {
            id: "in_fail_123",
            customer: "cus_123",
            amount_due: 5000,
            amount_paid: 0,
            currency: "usd",
          },
        },
      });
      mockStorage.getSubscriptionByStripeCustomerId.mockResolvedValue({
        id: "sub-local-1",
        orgId: "org-1",
        status: "active",
      });
      mockStorage.getInvoiceByStripeId.mockResolvedValue(null);

      await mod.handleWebhookEvent(Buffer.from("{}"), "sig");

      expect(mockStorage.updateSubscription).toHaveBeenCalledWith("sub-local-1", { status: "past_due" });
      expect(mockStorage.createInvoice).toHaveBeenCalledWith(
        expect.objectContaining({
          status: "open",
          amountPaidCents: 0,
        }),
      );
    });

    it("routes customer.subscription.updated to subscription update logic", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "customer.subscription.updated",
        id: "evt_sub_upd",
        data: {
          object: {
            id: "sub_stripe_123",
            status: "active",
            current_period_start: 1700000000,
            current_period_end: 1702600000,
            trial_end: null,
          },
        },
      });
      mockStorage.getSubscriptionByStripeSubId.mockResolvedValue({
        id: "sub-local-1",
        orgId: "org-1",
        status: "trialing",
      });

      await mod.handleWebhookEvent(Buffer.from("{}"), "sig");

      expect(mockStorage.updateSubscription).toHaveBeenCalledWith(
        "sub-local-1",
        expect.objectContaining({ status: "active" }),
      );
    });

    it("routes customer.subscription.deleted to subscription deletion logic", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "customer.subscription.deleted",
        id: "evt_sub_del",
        data: {
          object: {
            id: "sub_stripe_123",
            status: "canceled",
            current_period_end: 1702600000,
          },
        },
      });
      mockStorage.getSubscriptionByStripeSubId.mockResolvedValue({
        id: "sub-local-1",
        orgId: "org-1",
        status: "active",
      });

      await mod.handleWebhookEvent(Buffer.from("{}"), "sig");

      expect(mockStorage.updateSubscription).toHaveBeenCalledWith(
        "sub-local-1",
        expect.objectContaining({ status: "cancelled" }),
      );
    });

    it("routes customer.subscription.trial_will_end to trial ending notification", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "customer.subscription.trial_will_end",
        id: "evt_trial_end",
        data: {
          object: {
            id: "sub_stripe_123",
            status: "trialing",
            trial_end: 1702600000,
          },
        },
      });
      mockStorage.getSubscriptionByStripeSubId.mockResolvedValue({
        id: "sub-local-1",
        orgId: "org-1",
        status: "trialing",
      });

      await mod.handleWebhookEvent(Buffer.from("{}"), "sig");

      // Verifies the handler was reached -- getOrgMemberships called to find owner for email
      expect(mockStorage.getOrgMemberships).toHaveBeenCalledWith("org-1");
    });

    it("logs and ignores unknown event types without throwing", async () => {
      const mod = await importFresh();
      mockConstructEvent.mockReturnValue({
        type: "some.unknown.event",
        id: "evt_unknown",
        data: { object: {} },
      });

      // Should not throw
      await expect(mod.handleWebhookEvent(Buffer.from("{}"), "sig")).resolves.toBeUndefined();
    });
  });

  describe("getUsageVsLimits", () => {
    it("returns correct structure with plan info and usage metrics", async () => {
      vi.resetModules();
      process.env.STRIPE_SECRET_KEY = "sk_test_key";
      const mod = await import("../stripe-service");

      mockStorage.getSubscription.mockResolvedValue({
        id: "sub-1",
        planId: "plan-pro",
        orgId: "org-1",
      });
      mockStorage.getPlan.mockResolvedValue({
        name: "pro",
        displayName: "Professional",
      });

      const result = await mod.getUsageVsLimits("org-1");

      expect(result).toHaveProperty("plan");
      expect(result).toHaveProperty("usage");
      expect(result.plan).toEqual(
        expect.objectContaining({ name: "pro", displayName: "Professional" }),
      );
      expect(result.usage.users).toEqual(
        expect.objectContaining({ current: 5, limit: 50, pct: 10, status: "ok" }),
      );
    });

    it("returns free plan info when no subscription exists", async () => {
      vi.resetModules();
      process.env.STRIPE_SECRET_KEY = "sk_test_key";
      const mod = await import("../stripe-service");

      mockStorage.getSubscription.mockResolvedValue(null);

      const result = await mod.getUsageVsLimits("org-2");

      expect(result.plan.name).toBe("free");
      expect(result.plan.displayName).toBe("Free");
    });
  });
});
