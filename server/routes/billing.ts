import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { storage, logger, getOrgId, sendEnvelope } from "./shared";
import {
  isStripeEnabled,
  createCheckoutSession,
  createPortalSession,
  changePlan,
  cancelSubscription,
  reactivateSubscription,
  handleWebhookEvent,
  getUsageVsLimits,
} from "../stripe-service";

const log = logger.child("billing");

export function registerBillingRoutes(app: Express): void {
  app.get("/api/billing/plans", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      const plansList = await storage.getPlans(true);
      return sendEnvelope(res, plansList);
    } catch (err) {
      log.error("Failed to fetch plans", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "PLANS_FETCH_FAILED", message: "Failed to fetch plans" }],
      });
    }
  });

  app.get(
    "/api/billing/subscription",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const sub = await storage.getSubscription(orgId);
        if (!sub) {
          const freePlan = await storage.getPlanByName("free");
          return sendEnvelope(res, {
            subscription: null,
            plan: freePlan || { name: "free", displayName: "Free", monthlyPriceCents: 0 },
            status: "active",
            isFreePlan: true,
          });
        }
        const plan = await storage.getPlan(sub.planId);
        return sendEnvelope(res, {
          subscription: sub,
          plan,
          status: sub.status,
          isFreePlan: plan?.name === "free",
        });
      } catch (err) {
        log.error("Failed to fetch subscription", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SUB_FETCH_FAILED", message: "Failed to fetch subscription" }],
        });
      }
    },
  );

  app.post(
    "/api/billing/checkout-session",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        if (!isStripeEnabled()) {
          return sendEnvelope(res, null, {
            status: 503,
            errors: [{ code: "STRIPE_DISABLED", message: "Stripe integration is not configured" }],
          });
        }
        const orgId = getOrgId(req);
        const { planId, billingCycle, successUrl, cancelUrl } = req.body;
        if (!planId || !successUrl || !cancelUrl) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_FIELDS", message: "planId, successUrl, and cancelUrl are required" }],
          });
        }
        const user = (req as any).user;
        const result = await createCheckoutSession({
          orgId,
          planId,
          billingCycle: billingCycle || "monthly",
          successUrl,
          cancelUrl,
          customerEmail: user?.email,
        });
        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to create checkout session", { error: String(err) });
        return sendEnvelope(res, null, { status: 500, errors: [{ code: "CHECKOUT_FAILED", message: String(err) }] });
      }
    },
  );

  app.post(
    "/api/billing/portal-session",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        if (!isStripeEnabled()) {
          return sendEnvelope(res, null, {
            status: 503,
            errors: [{ code: "STRIPE_DISABLED", message: "Stripe integration is not configured" }],
          });
        }
        const orgId = getOrgId(req);
        const { returnUrl } = req.body;
        if (!returnUrl) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_FIELDS", message: "returnUrl is required" }],
          });
        }
        const result = await createPortalSession({ orgId, returnUrl });
        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to create portal session", { error: String(err) });
        return sendEnvelope(res, null, { status: 500, errors: [{ code: "PORTAL_FAILED", message: String(err) }] });
      }
    },
  );

  app.post(
    "/api/billing/change-plan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        if (!isStripeEnabled()) {
          return sendEnvelope(res, null, {
            status: 503,
            errors: [{ code: "STRIPE_DISABLED", message: "Stripe integration is not configured" }],
          });
        }
        const orgId = getOrgId(req);
        const { newPlanId, billingCycle } = req.body;
        if (!newPlanId) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_FIELDS", message: "newPlanId is required" }],
          });
        }
        const success = await changePlan({ orgId, newPlanId, billingCycle });
        return sendEnvelope(res, { success });
      } catch (err) {
        log.error("Failed to change plan", { error: String(err) });
        return sendEnvelope(res, null, { status: 500, errors: [{ code: "CHANGE_PLAN_FAILED", message: String(err) }] });
      }
    },
  );

  app.post(
    "/api/billing/cancel",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        if (!isStripeEnabled()) {
          return sendEnvelope(res, null, {
            status: 503,
            errors: [{ code: "STRIPE_DISABLED", message: "Stripe integration is not configured" }],
          });
        }
        const orgId = getOrgId(req);
        const { reason, immediate } = req.body;
        const success = await cancelSubscription({ orgId, reason, immediate: immediate === true });
        return sendEnvelope(res, { success });
      } catch (err) {
        log.error("Failed to cancel subscription", { error: String(err) });
        return sendEnvelope(res, null, { status: 500, errors: [{ code: "CANCEL_FAILED", message: String(err) }] });
      }
    },
  );

  app.post(
    "/api/billing/reactivate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        if (!isStripeEnabled()) {
          return sendEnvelope(res, null, {
            status: 503,
            errors: [{ code: "STRIPE_DISABLED", message: "Stripe integration is not configured" }],
          });
        }
        const orgId = getOrgId(req);
        const success = await reactivateSubscription({ orgId });
        return sendEnvelope(res, { success });
      } catch (err) {
        log.error("Failed to reactivate subscription", { error: String(err) });
        return sendEnvelope(res, null, { status: 500, errors: [{ code: "REACTIVATE_FAILED", message: String(err) }] });
      }
    },
  );

  app.get(
    "/api/billing/invoices",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 50;
        const invoicesList = await storage.getInvoices(orgId, limit);
        return sendEnvelope(res, invoicesList);
      } catch (err) {
        log.error("Failed to fetch invoices", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INVOICES_FETCH_FAILED", message: "Failed to fetch invoices" }],
        });
      }
    },
  );

  app.get(
    "/api/billing/usage-vs-limits",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await getUsageVsLimits(orgId);
        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to fetch usage vs limits", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "USAGE_FETCH_FAILED", message: "Failed to fetch usage data" }],
        });
      }
    },
  );

  app.post("/api/billing/webhook", async (req: Request, res: Response) => {
    try {
      const signature = req.headers["stripe-signature"] as string;
      if (!signature) {
        return res.status(400).json({ error: "Missing stripe-signature header" });
      }
      const rawBody = req.rawBody;
      if (!rawBody || !Buffer.isBuffer(rawBody)) {
        return res.status(400).json({ error: "Raw body not available for signature verification" });
      }
      await handleWebhookEvent(rawBody, signature);
      return res.status(200).json({ received: true });
    } catch (err) {
      log.error("Webhook processing failed", { error: String(err) });
      return res.status(400).json({ error: "Webhook verification failed" });
    }
  });
}
