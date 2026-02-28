import Stripe from "stripe";
import { storage } from "./storage";
import { logger } from "./logger";
import { config } from "./config";
import { sendEmail } from "./email-service";
import { paymentFailedEmail, trialEndingEmail, subscriptionCancelledEmail } from "./email-templates";
import { authStorage } from "./auth/storage";

const log = logger.child("stripe");

function getStripeClient(): Stripe | null {
  const secretKey = process.env.STRIPE_SECRET_KEY;
  if (!secretKey) {
    log.warn("STRIPE_SECRET_KEY not configured — Stripe integration disabled");
    return null;
  }
  return new Stripe(secretKey, { apiVersion: "2025-01-27.acacia" as Stripe.LatestApiVersion });
}

let stripeClient: Stripe | null | undefined;

function stripe(): Stripe | null {
  if (stripeClient === undefined) {
    stripeClient = getStripeClient();
  }
  return stripeClient;
}

export function isStripeEnabled(): boolean {
  return stripe() !== null;
}

export async function createCheckoutSession(params: {
  orgId: string;
  planId: string;
  billingCycle: "monthly" | "annual";
  successUrl: string;
  cancelUrl: string;
  customerEmail?: string;
}): Promise<{ url: string } | null> {
  const client = stripe();
  if (!client) return null;

  const plan = await storage.getPlan(params.planId);
  if (!plan) throw new Error("Plan not found");

  const priceId = params.billingCycle === "annual" ? plan.stripePriceIdAnnual : plan.stripePriceIdMonthly;

  if (!priceId) throw new Error(`No Stripe price configured for plan ${plan.name} (${params.billingCycle})`);

  const existingSub = await storage.getSubscription(params.orgId);
  const customerOptions: Stripe.Checkout.SessionCreateParams = {
    mode: "subscription",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    metadata: { orgId: params.orgId, planId: params.planId, billingCycle: params.billingCycle },
    subscription_data: { metadata: { orgId: params.orgId } },
  };

  if (existingSub?.stripeCustomerId) {
    customerOptions.customer = existingSub.stripeCustomerId;
  } else if (params.customerEmail) {
    customerOptions.customer_email = params.customerEmail;
  }

  const session = await client.checkout.sessions.create(customerOptions);
  return { url: session.url || "" };
}

export async function createPortalSession(params: {
  orgId: string;
  returnUrl: string;
}): Promise<{ url: string } | null> {
  const client = stripe();
  if (!client) return null;

  const sub = await storage.getSubscription(params.orgId);
  if (!sub?.stripeCustomerId) throw new Error("No Stripe customer found for this organization");

  const session = await client.billingPortal.sessions.create({
    customer: sub.stripeCustomerId,
    return_url: params.returnUrl,
  });

  return { url: session.url };
}

export async function changePlan(params: {
  orgId: string;
  newPlanId: string;
  billingCycle?: "monthly" | "annual";
}): Promise<boolean> {
  const client = stripe();
  if (!client) return false;

  const sub = await storage.getSubscription(params.orgId);
  if (!sub?.stripeSubscriptionId) throw new Error("No active Stripe subscription");

  const newPlan = await storage.getPlan(params.newPlanId);
  if (!newPlan) throw new Error("Target plan not found");

  const cycle = params.billingCycle || sub.billingCycle || "monthly";
  const priceId = cycle === "annual" ? newPlan.stripePriceIdAnnual : newPlan.stripePriceIdMonthly;
  if (!priceId) throw new Error(`No Stripe price for plan ${newPlan.name} (${cycle})`);

  const stripeSub = await client.subscriptions.retrieve(sub.stripeSubscriptionId);
  const itemId = stripeSub.items.data[0]?.id;
  if (!itemId) throw new Error("No subscription item found");

  await client.subscriptions.update(sub.stripeSubscriptionId, {
    items: [{ id: itemId, price: priceId }],
    proration_behavior: "create_prorations",
    metadata: { orgId: params.orgId, planId: params.newPlanId },
  });

  await storage.updateSubscription(sub.id, {
    planId: params.newPlanId,
    billingCycle: cycle,
  });

  return true;
}

export async function cancelSubscription(params: {
  orgId: string;
  reason?: string;
  immediate?: boolean;
}): Promise<boolean> {
  const client = stripe();
  if (!client) return false;

  const sub = await storage.getSubscription(params.orgId);
  if (!sub?.stripeSubscriptionId) throw new Error("No active Stripe subscription");

  if (params.immediate) {
    await client.subscriptions.cancel(sub.stripeSubscriptionId);
  } else {
    await client.subscriptions.update(sub.stripeSubscriptionId, {
      cancel_at_period_end: true,
    });
  }

  await storage.updateSubscription(sub.id, {
    status: params.immediate ? "cancelled" : sub.status,
    cancelledAt: new Date(),
    cancelReason: params.reason || "user_requested",
  });

  return true;
}

export async function reactivateSubscription(params: { orgId: string }): Promise<boolean> {
  const client = stripe();
  if (!client) return false;

  const sub = await storage.getSubscription(params.orgId);
  if (!sub?.stripeSubscriptionId) throw new Error("No subscription to reactivate");

  await client.subscriptions.update(sub.stripeSubscriptionId, {
    cancel_at_period_end: false,
  });

  await storage.updateSubscription(sub.id, {
    cancelledAt: null,
    cancelReason: null,
  });

  return true;
}

export async function handleWebhookEvent(rawBody: Buffer, signature: string): Promise<void> {
  const client = stripe();
  if (!client) throw new Error("Stripe not configured");

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) throw new Error("STRIPE_WEBHOOK_SECRET not configured");

  const event = client.webhooks.constructEvent(rawBody, signature, webhookSecret);
  log.info("Processing Stripe webhook", { type: event.type, id: event.id });

  switch (event.type) {
    case "checkout.session.completed":
      await handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
      break;
    case "invoice.paid":
      await handleInvoicePaid(event.data.object as Stripe.Invoice);
      break;
    case "invoice.payment_failed":
      await handleInvoicePaymentFailed(event.data.object as Stripe.Invoice);
      break;
    case "customer.subscription.updated":
      await handleSubscriptionUpdated(event.data.object as Stripe.Subscription);
      break;
    case "customer.subscription.deleted":
      await handleSubscriptionDeleted(event.data.object as Stripe.Subscription);
      break;
    case "customer.subscription.trial_will_end":
      await handleTrialWillEnd(event.data.object as Stripe.Subscription);
      break;
    default:
      log.info("Unhandled Stripe event type", { type: event.type });
  }
}

async function handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
  const orgId = session.metadata?.orgId;
  const planId = session.metadata?.planId;
  const billingCycle = (session.metadata?.billingCycle as "monthly" | "annual") || "monthly";
  if (!orgId || !planId) {
    log.warn("checkout.session.completed missing metadata", { sessionId: session.id });
    return;
  }

  const customerId = typeof session.customer === "string" ? session.customer : session.customer?.id;
  const subscriptionId = typeof session.subscription === "string" ? session.subscription : session.subscription?.id;

  const existing = await storage.getSubscription(orgId);
  if (existing) {
    await storage.updateSubscription(existing.id, {
      planId,
      billingCycle,
      status: "active",
      stripeCustomerId: customerId || existing.stripeCustomerId,
      stripeSubscriptionId: subscriptionId || existing.stripeSubscriptionId,
    });
  } else {
    await storage.createSubscription({
      orgId,
      planId,
      billingCycle,
      status: "active",
      stripeCustomerId: customerId || null,
      stripeSubscriptionId: subscriptionId || null,
    });
  }

  log.info("Subscription activated via checkout", { orgId, planId });
}

async function handleInvoicePaid(invoice: Stripe.Invoice): Promise<void> {
  const stripeInvoiceId = invoice.id;
  const customerId = typeof invoice.customer === "string" ? invoice.customer : invoice.customer?.id;
  if (!customerId) return;

  const sub = await storage.getSubscriptionByStripeCustomerId(customerId);
  if (!sub) {
    log.warn("invoice.paid: no subscription for customer", { customerId });
    return;
  }

  const existing = await storage.getInvoiceByStripeId(stripeInvoiceId);
  if (existing) {
    await storage.updateInvoice(existing.id, {
      status: "paid",
      amountPaidCents: invoice.amount_paid,
      paidAt: new Date(),
      pdfUrl: invoice.invoice_pdf || null,
      hostedUrl: invoice.hosted_invoice_url || null,
    });
  } else {
    await storage.createInvoice({
      orgId: sub.orgId,
      subscriptionId: sub.id,
      stripeInvoiceId,
      amountDueCents: invoice.amount_due,
      amountPaidCents: invoice.amount_paid,
      currency: invoice.currency,
      status: "paid",
      pdfUrl: invoice.invoice_pdf || null,
      hostedUrl: invoice.hosted_invoice_url || null,
      periodStart: invoice.period_start ? new Date(invoice.period_start * 1000) : null,
      periodEnd: invoice.period_end ? new Date(invoice.period_end * 1000) : null,
      paidAt: new Date(),
    });
  }

  if (sub.status === "past_due") {
    await storage.updateSubscription(sub.id, { status: "active" });
  }
}

async function handleInvoicePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
  const customerId = typeof invoice.customer === "string" ? invoice.customer : invoice.customer?.id;
  if (!customerId) return;

  const sub = await storage.getSubscriptionByStripeCustomerId(customerId);
  if (!sub) return;

  await storage.updateSubscription(sub.id, { status: "past_due" });

  const existing = await storage.getInvoiceByStripeId(invoice.id);
  if (existing) {
    await storage.updateInvoice(existing.id, { status: "open" });
  } else {
    await storage.createInvoice({
      orgId: sub.orgId,
      subscriptionId: sub.id,
      stripeInvoiceId: invoice.id,
      amountDueCents: invoice.amount_due,
      amountPaidCents: 0,
      currency: invoice.currency,
      status: "open",
      periodStart: invoice.period_start ? new Date(invoice.period_start * 1000) : null,
      periodEnd: invoice.period_end ? new Date(invoice.period_end * 1000) : null,
    });
  }

  log.warn("Invoice payment failed", { orgId: sub.orgId, invoiceId: invoice.id });

  sendOrgOwnerEmail(sub.orgId, (ownerEmail, org) => {
    const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
    return paymentFailedEmail({
      orgName: org?.name || "your organization",
      amountDue: `$${(invoice.amount_due / 100).toFixed(2)}`,
      retryDate: invoice.next_payment_attempt
        ? new Date(invoice.next_payment_attempt * 1000).toLocaleDateString("en-US", {
            month: "long",
            day: "numeric",
            year: "numeric",
          })
        : undefined,
      billingUrl: `${appBaseUrl}/billing`,
    });
  }).catch((err) => log.error("Failed to send payment-failed email", { error: String(err) }));
}

async function handleSubscriptionUpdated(stripeSub: Stripe.Subscription): Promise<void> {
  const sub = await storage.getSubscriptionByStripeSubId(stripeSub.id);
  if (!sub) {
    log.warn("subscription.updated: no local subscription found", { stripeSubId: stripeSub.id });
    return;
  }

  const statusMap: Record<string, string> = {
    active: "active",
    past_due: "past_due",
    canceled: "cancelled",
    unpaid: "past_due",
    trialing: "trialing",
    paused: "paused",
  };

  await storage.updateSubscription(sub.id, {
    status: statusMap[stripeSub.status] || sub.status,
    currentPeriodStart: (stripeSub as any).current_period_start
      ? new Date((stripeSub as any).current_period_start * 1000)
      : null,
    currentPeriodEnd: (stripeSub as any).current_period_end
      ? new Date((stripeSub as any).current_period_end * 1000)
      : null,
    trialEndDate: stripeSub.trial_end ? new Date(stripeSub.trial_end * 1000) : null,
  });
}

async function handleSubscriptionDeleted(stripeSub: Stripe.Subscription): Promise<void> {
  const sub = await storage.getSubscriptionByStripeSubId(stripeSub.id);
  if (!sub) return;

  await storage.updateSubscription(sub.id, {
    status: "cancelled",
    cancelledAt: new Date(),
  });

  log.info("Subscription cancelled via Stripe", { orgId: sub.orgId });

  sendOrgOwnerEmail(sub.orgId, (ownerEmail, org) => {
    const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
    const periodEnd = (stripeSub as any).current_period_end as number | null;
    const accessEndDate = periodEnd
      ? new Date(periodEnd * 1000).toLocaleDateString("en-US", {
          month: "long",
          day: "numeric",
          year: "numeric",
        })
      : "end of current billing period";
    return subscriptionCancelledEmail({
      orgName: org?.name || "your organization",
      accessEndDate,
      reactivateUrl: `${appBaseUrl}/billing`,
    });
  }).catch((err) => log.error("Failed to send subscription-cancelled email", { error: String(err) }));
}

async function handleTrialWillEnd(stripeSub: Stripe.Subscription): Promise<void> {
  const sub = await storage.getSubscriptionByStripeSubId(stripeSub.id);
  if (!sub) return;

  log.info("Trial ending soon", {
    orgId: sub.orgId,
    trialEnd: stripeSub.trial_end ? new Date(stripeSub.trial_end * 1000).toISOString() : "unknown",
  });

  sendOrgOwnerEmail(sub.orgId, (ownerEmail, org) => {
    const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
    const trialEndDate = stripeSub.trial_end
      ? new Date(stripeSub.trial_end * 1000).toLocaleDateString("en-US", {
          month: "long",
          day: "numeric",
          year: "numeric",
        })
      : "soon";
    return trialEndingEmail({
      orgName: org?.name || "your organization",
      trialEndDate,
      billingUrl: `${appBaseUrl}/billing`,
    });
  }).catch((err) => log.error("Failed to send trial-ending email", { error: String(err) }));
}

async function sendOrgOwnerEmail(
  orgId: string,
  buildEmail: (
    ownerEmail: string,
    org: { name: string } | undefined,
  ) => { subject: string; html: string; text: string },
): Promise<void> {
  const memberships = await storage.getOrgMemberships(orgId);
  const ownerMembership = memberships.find((m) => m.role === "owner" && m.status === "active");
  if (!ownerMembership) {
    log.warn("No active owner found for org — skipping email", { orgId });
    return;
  }
  const ownerUser = await authStorage.getUser(ownerMembership.userId);
  if (!ownerUser?.email) {
    log.warn("Owner has no email — skipping email", { orgId, userId: ownerMembership.userId });
    return;
  }
  const org = await storage.getOrganization(orgId);
  const emailContent = buildEmail(ownerUser.email, org);
  await sendEmail({
    to: ownerUser.email,
    subject: emailContent.subject,
    html: emailContent.html,
    text: emailContent.text,
  });
}

export async function getUsageVsLimits(orgId: string): Promise<{
  plan: { name: string; displayName: string; tier: string };
  usage: Record<string, { current: number; limit: number; pct: number; status: string }>;
}> {
  const { getUsageSummary } = await import("./middleware/plan-enforcement");
  const summary = await getUsageSummary(orgId);

  const sub = await storage.getSubscription(orgId);
  let planInfo = { name: "free", displayName: "Free", tier: summary.tier };
  if (sub) {
    const plan = await storage.getPlan(sub.planId);
    if (plan) {
      planInfo = { name: plan.name, displayName: plan.displayName, tier: summary.tier };
    }
  }

  const usage: Record<string, { current: number; limit: number; pct: number; status: string }> = {};
  for (const [metric, data] of Object.entries(summary.metrics)) {
    usage[metric] = {
      current: data.current,
      limit: data.limit,
      pct: data.pct,
      status: data.status,
    };
  }

  return { plan: planInfo, usage };
}
